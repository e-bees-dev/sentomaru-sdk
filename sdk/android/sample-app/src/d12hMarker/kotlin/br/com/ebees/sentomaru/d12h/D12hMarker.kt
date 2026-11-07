package br.com.ebees.sentomaru.d12h

/**
 * D-12h: only in the raspLab build with -Psentomaru.d12h=dexMarker. Nothing references
 * or loads this class; it only changes the bytes of classes*.dex, so the code aggregate differs from the registered
 * build while the certificate and the versionCode stay the same.
 */
object D12hMarker {
    const val VALUE = "d12h-dex-marker"
}
