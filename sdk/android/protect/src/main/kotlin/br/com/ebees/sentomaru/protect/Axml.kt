package br.com.ebees.sentomaru.protect

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * G-03b3: an editor for Android binary XML (the manifest of an APK). It reads the string pool, the resource map and the
 * node chunks, keeps every node chunk byte for byte, and only ever APPENDS: new strings go to the end of the pool, so no
 * existing string index moves; a new attribute name that needs a resource id gets its slot in the resource map (the map is
 * padded with 0, "no resource", up to it). New elements are built as whole chunks and inserted before an end-element chunk
 * or a start-element chunk. Nothing else of the document is interpreted or rewritten.
 *
 * Every offset and count is checked against its chunk before use (the input is untrusted): a malformed document is
 * `input-format`, never an out-of-memory error or an endless walk.
 */
internal class Axml private constructor(
    private var utf8: Boolean,
    private val strings: MutableList<String>,
    private val resourceIds: MutableList<Int>,
    private val chunks: MutableList<Chunk>,
) {
    class Attr(val namespace: Int, val name: Int, val raw: Int, val type: Int, val data: Int)

    /** One node chunk, whole (header included). [element] is set for a start-element chunk. */
    class Chunk(val type: Int, val bytes: ByteArray, val element: Element? = null)
    class Element(val namespace: Int, val name: Int, val attributes: List<Attr>)

    /** A start-element chunk and its matching end-element chunk (indices in the node list) and its depth (manifest is 0). */
    class Span(val start: Int, val end: Int, val depth: Int)

    fun string(index: Int): String = strings.getOrElse(index) { "" }

    fun indexOf(value: String): Int = strings.indexOf(value)

    /** The index of [value], appended to the pool when it is not there. */
    fun intern(value: String): Int {
        val found = strings.indexOf(value)
        if (found >= 0) return found
        strings += value
        return strings.size - 1
    }

    /** The index of an attribute-name string that maps to [resourceId]; appended (and mapped) when no such string exists. */
    fun attributeName(name: String, resourceId: Int): Int {
        for (i in strings.indices) if (strings[i] == name && resourceIds.getOrNull(i) == resourceId) return i
        strings += name
        val index = strings.size - 1
        while (resourceIds.size < index) resourceIds += 0
        resourceIds += resourceId
        return index
    }

    fun resourceId(index: Int): Int? = resourceIds.getOrNull(index)

    /** Every element with its span, in document order. */
    fun spans(): List<Pair<Element, Span>> {
        val result = mutableListOf<Pair<Element, Span>>()
        val open = ArrayDeque<Int>()
        for ((i, chunk) in chunks.withIndex()) {
            when (chunk.type) {
                START_ELEMENT -> { open.addLast(result.size); result += chunk.element!! to Span(i, -1, open.size - 1) }
                END_ELEMENT -> {
                    val at = open.removeLastOrNull() ?: throw ProtectException(ErrorCode.INPUT_FORMAT, "binary manifest: unbalanced elements")
                    val (element, span) = result[at]
                    result[at] = element to Span(span.start, i, span.depth)
                }
            }
        }
        if (open.isNotEmpty()) throw ProtectException(ErrorCode.INPUT_FORMAT, "binary manifest: unbalanced elements")
        return result
    }

    /** Inserts whole chunks before node [index]. */
    fun insertBefore(index: Int, added: List<Chunk>) {
        chunks.addAll(index, added)
    }

    fun toBytes(): ByteArray {
        val pool = encodePool()
        val map = if (resourceIds.isEmpty()) ByteArray(0) else ByteBuffer.allocate(8 + resourceIds.size * 4).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(RESOURCE_MAP.toShort()); putShort(8); putInt(8 + resourceIds.size * 4); resourceIds.forEach { putInt(it) }
        }.array()
        val total = 8 + pool.size + map.size + chunks.sumOf { it.bytes.size }
        val out = ByteArrayOutputStream(total)
        out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putShort(DOCUMENT.toShort()).putShort(8).putInt(total).array())
        out.write(pool)
        out.write(map)
        chunks.forEach { out.write(it.bytes) }
        return out.toByteArray()
    }

    private fun encodePool(): ByteArray {
        val encoded = strings.map { if (utf8) utf8Entry(it) else utf16Entry(it) }
        val header = 28
        val offsets = IntArray(encoded.size)
        var cursor = 0
        encoded.forEachIndexed { i, e -> offsets[i] = cursor; cursor += e.size }
        val stringsStart = header + 4 * encoded.size
        val padded = (cursor + 3) and 3.inv()
        val buffer = ByteBuffer.allocate(stringsStart + padded).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putShort(STRING_POOL.toShort()).putShort(header.toShort()).putInt(stringsStart + padded)
        buffer.putInt(encoded.size).putInt(0).putInt(if (utf8) UTF8_FLAG else 0).putInt(stringsStart).putInt(0)
        offsets.forEach { buffer.putInt(it) }
        encoded.forEach { buffer.put(it) }
        return buffer.array()
    }

    companion object {
        const val DOCUMENT = 0x0003
        const val STRING_POOL = 0x0001
        const val RESOURCE_MAP = 0x0180
        const val START_NAMESPACE = 0x0100
        const val END_NAMESPACE = 0x0101
        const val START_ELEMENT = 0x0102
        const val END_ELEMENT = 0x0103
        private const val UTF8_FLAG = 0x100
        private const val NONE = -1
        private const val MAX_STRING = 0x7fff

        const val TYPE_STRING = 0x03
        const val TYPE_BOOLEAN = 0x12

        private fun bad(detail: String): Nothing = throw ProtectException(ErrorCode.INPUT_FORMAT, "binary manifest: $detail")

        private fun utf8Entry(s: String): ByteArray {
            val bytes = s.toByteArray(Charsets.UTF_8)
            if (s.length > MAX_STRING || bytes.size > MAX_STRING) bad("string too long to write")
            fun length(n: Int) = if (n > 0x7f) byteArrayOf((0x80 or (n shr 8)).toByte(), n.toByte()) else byteArrayOf(n.toByte())
            return length(s.length) + length(bytes.size) + bytes + byteArrayOf(0)
        }

        private fun utf16Entry(s: String): ByteArray {
            if (s.length > MAX_STRING) bad("string too long to write")
            val buffer = ByteBuffer.allocate(2 + s.length * 2 + 2).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putShort(s.length.toShort())
            s.forEach { buffer.putShort(it.code.toShort()) }
            return buffer.array()
        }

        /** A start-element chunk for a new element without namespace declarations (line 0, no comment). */
        fun startElement(namespace: Int, name: Int, attributes: List<Attr>): Chunk {
            val size = 36 + attributes.size * 20
            val b = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
            b.putShort(START_ELEMENT.toShort()).putShort(16).putInt(size).putInt(0).putInt(NONE)
            b.putInt(namespace).putInt(name).putShort(20).putShort(20).putShort(attributes.size.toShort())
            b.putShort(0).putShort(0).putShort(0)
            for (a in attributes) {
                b.putInt(a.namespace).putInt(a.name).putInt(a.raw)
                b.putShort(8).put(0).put(a.type.toByte()).putInt(a.data)
            }
            return Chunk(START_ELEMENT, b.array(), Element(namespace, name, attributes))
        }

        fun endElement(namespace: Int, name: Int): Chunk {
            val b = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            b.putShort(END_ELEMENT.toShort()).putShort(16).putInt(24).putInt(0).putInt(NONE).putInt(namespace).putInt(name)
            return Chunk(END_ELEMENT, b.array())
        }

        fun parse(bytes: ByteArray): Axml {
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val all = bytes.size.toLong()
            fun u16(o: Long, end: Long): Int { if (o < 0 || o + 2 > end) bad("truncated"); return b.getShort(o.toInt()).toInt() and 0xffff }
            fun u32(o: Long, end: Long): Long { if (o < 0 || o + 4 > end) bad("truncated"); return b.getInt(o.toInt()).toLong() and 0xffffffffL }
            if (u16(0, all) != DOCUMENT) bad("header")
            val headerSize = u16(2, all).toLong()
            val end = minOf(u32(4, all), all)
            if (headerSize < 8 || headerSize > end) bad("header")
            var utf8 = false
            var strings: MutableList<String>? = null
            var ids = mutableListOf<Int>()
            val nodes = mutableListOf<Chunk>()
            var offset = headerSize
            var decoded = 0L
            while (offset + 8 <= end) {
                val type = u16(offset, end)
                val hs = u16(offset + 2, end).toLong()
                val size = u32(offset + 4, end)
                if (hs < 8 || size < hs || offset + size > end) bad("chunk bounds")
                val chunkEnd = offset + size
                when (type) {
                    STRING_POOL -> {
                        if (strings != null) bad("second string pool")
                        if (hs < 28) bad("string pool header")
                        val count = u32(offset + 8, chunkEnd)
                        if (count * 4 > chunkEnd - offset - hs) bad("string count")
                        if (u32(offset + 12, chunkEnd) != 0L) bad("styled strings are not supported")
                        utf8 = u32(offset + 16, chunkEnd) and UTF8_FLAG.toLong() != 0L
                        val start = offset + u32(offset + 20, chunkEnd)
                        if (count > 0 && (start < offset + hs + count * 4 || start > chunkEnd)) bad("strings start")
                        val list = ArrayList<String>(count.toInt())
                        for (i in 0 until count.toInt()) {
                            var p = start + u32(offset + hs + i * 4L, chunkEnd)
                            val text: String
                            if (utf8) {
                                if (p < 0 || p + 4 > chunkEnd) bad("string beyond pool")
                                val chars = b.get(p.toInt()).toInt() and 0xff // UTF-16 length: not needed to decode
                                p += if (chars and 0x80 != 0) 2 else 1
                                var len = b.get(p.toInt()).toInt() and 0xff
                                if (len and 0x80 != 0) { len = ((len and 0x7f) shl 8) or (b.get(p.toInt() + 1).toInt() and 0xff); p += 2 } else p += 1
                                if (p + len > chunkEnd) bad("string beyond pool")
                                text = String(bytes, p.toInt(), len, Charsets.UTF_8)
                            } else {
                                var len = u16(p, chunkEnd).toLong()
                                if (len and 0x8000L != 0L) { len = ((len and 0x7fffL) shl 16) or u16(p + 2, chunkEnd).toLong(); p += 4 } else p += 2
                                if (p + len * 2 > chunkEnd) bad("string beyond pool")
                                text = String(CharArray(len.toInt()) { b.getChar((p + it * 2L).toInt()) })
                            }
                            decoded += text.length
                            if (decoded > 4L * 1024 * 1024) bad("strings above budget")
                            list += text
                        }
                        strings = list
                    }
                    RESOURCE_MAP -> {
                        ids = MutableList(((size - hs) / 4).toInt()) { b.getInt((offset + hs + it * 4L).toInt()) }
                    }
                    else -> {
                        val chunk = bytes.copyOfRange(offset.toInt(), chunkEnd.toInt())
                        if (type == START_ELEMENT) {
                            val ext = offset + hs
                            val attributeStart = u16(ext + 8, chunkEnd).toLong()
                            val attributeSize = u16(ext + 10, chunkEnd).toLong()
                            val count = u16(ext + 12, chunkEnd)
                            if (count > 0 && attributeSize < 20) bad("attribute size")
                            if (ext + attributeStart + count * attributeSize > chunkEnd) bad("attributes beyond chunk")
                            val attrs = (0 until count).map { i ->
                                val a = ext + attributeStart + i * attributeSize
                                Attr(u32(a, chunkEnd).toInt(), u32(a + 4, chunkEnd).toInt(), u32(a + 8, chunkEnd).toInt(),
                                    b.get((a + 15).toInt()).toInt() and 0xff, u32(a + 16, chunkEnd).toInt())
                            }
                            nodes += Chunk(type, chunk, Element(u32(ext, chunkEnd).toInt(), u32(ext + 4, chunkEnd).toInt(), attrs))
                        } else nodes += Chunk(type, chunk)
                    }
                }
                offset = chunkEnd
            }
            return Axml(utf8, strings ?: bad("no string pool"), ids, nodes)
        }
    }
}
