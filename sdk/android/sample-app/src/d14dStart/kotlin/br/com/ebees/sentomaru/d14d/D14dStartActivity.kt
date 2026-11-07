package br.com.ebees.sentomaru.d14d

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/**
 * D-14d, lab only (the `d14dSealed` build, never the default build): the launch target of the cold-start control. It
 * reads NOTHING sealed and does nothing else, on purpose: the asset-encryption design runs nothing at startup (the
 * reader is lazy, D-14b), so the sealed and the unsealed AAB of this build must start alike. A rise in cold start
 * with the section would be a defect (D-14x6), not a cost of reading.
 */
class D14dStartActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = "d14d" })
    }
}
