package io.github.cinnamon415.packetwall.e2e

import android.util.Base64
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail

private const val DOCS = "com.android.documentsui"

fun waitObj(sel: BySelector, timeoutMs: Long = 10_000, what: String = sel.toString()): UiObject2 =
    device.wait(Until.findObject(sel), timeoutMs) ?: run {
        fail("not on screen: $what")
        error("unreachable")
    }

/** The system file picker (DocumentsUI), driven like a user would. Files live in /sdcard/Download. */
object Docs {
    const val DIR = "/sdcard/Download"

    /** "Save as": the picker opened by the app; types [name] and saves into Download. Returns the path. */
    fun save(name: String): String {
        val field = waitObj(By.res("android:id/title").clazz("android.widget.EditText").pkg(DOCS), what = "save dialog")
        showDownload()
        field.text = name
        waitObj(By.res("android:id/button1").pkg(DOCS)).click()
        // replacing an existing file asks first
        device.wait(Until.findObject(By.res("android:id/button1").pkg(DOCS).textContains("OK")), 1000)?.click()
        device.wait(Until.gone(By.pkg(DOCS)), 10_000)
        return "$DIR/$name"
    }

    /** "Open": picks [name] in Download. */
    fun open(name: String) {
        waitObj(By.pkg(DOCS), what = "file picker")
        showDownload()
        // Download fills up with test files: the file may be further down the list
        if (device.wait(Until.hasObject(By.res("android:id/title").text(name)), 3000) != true) {
            runCatching {
                androidx.test.uiautomator.UiScrollable(androidx.test.uiautomator.UiSelector().scrollable(true)).scrollTextIntoView(name)
            }
        }
        val item = device.wait(Until.findObject(By.res("android:id/title").text(name)), 3000)
            ?: run {
                // a picker opened on "Recent" lists nothing until a root is chosen
                showDownload(force = true)
                waitObj(By.res("android:id/title").text(name), what = "file $name in the picker")
            }
        item.click()
        device.wait(Until.gone(By.pkg(DOCS)), 10_000)
    }

    /** Folder picker: opens Download/[dir] and grants access to it. */
    fun useFolder(dir: String) {
        waitObj(By.pkg(DOCS), what = "folder picker")
        // it may reopen where it was last used: already inside the folder
        val inside = device.wait(Until.findObject(By.res("$DOCS:id/breadcrumb_text").text(dir)), 3000)
        if (inside == null) openFolder(dir)
        clickFresh(By.res("android:id/button1").pkg(DOCS).textContains("USE THIS FOLDER"), "use this folder")
        // "Allow Packetwall to access files in …?"
        clickFresh(By.res("android:id/button1").pkg(DOCS).textContains("ALLOW"), "allow access")
        device.wait(Until.gone(By.pkg(DOCS)), 10_000)
    }

    private fun openFolder(dir: String) {
        // the folder picker opens on the storage root, where Download is a folder (not a root of its own)
        val download = device.wait(Until.findObject(By.res("android:id/title").text("Download").pkg(DOCS)), 5000)
        if (download != null && !device.hasObject(By.res("$DOCS:id/breadcrumb_text").text("Download"))) download.click() else showDownload()
        waitObj(By.res("$DOCS:id/breadcrumb_text").text("Download"), what = "in Download")
        device.waitForIdle()
        // Download fills up with test files: the folder may be further down the list
        if (!device.hasObject(By.res("android:id/title").text(dir))) {
            runCatching {
                androidx.test.uiautomator.UiScrollable(androidx.test.uiautomator.UiSelector().scrollable(true)).scrollTextIntoView(dir)
            }
        }
        clickFresh(By.res("android:id/title").text(dir), "folder $dir")
        waitObj(By.res("$DOCS:id/breadcrumb_text").text(dir), what = "in $dir")
    }

    /** Clicks [sel]; the picker rebuilds its views while it loads, so a stale view is looked up again. */
    private fun clickFresh(sel: BySelector, what: String) {
        repeat(4) {
            try {
                waitObj(sel, what = what).click()
                return
            } catch (e: androidx.test.uiautomator.StaleObjectException) {
                device.waitForIdle()
            }
        }
        waitObj(sel, what = what).click()
    }

    fun cancel() {
        device.pressBack()
        device.wait(Until.gone(By.pkg(DOCS)), 5000)
    }

    private fun showDownload(force: Boolean = false) {
        // the picker rebuilds its views while it loads: retry on a stale view
        repeat(3) {
            try {
                showDownloadOnce(force)
                return
            } catch (e: androidx.test.uiautomator.StaleObjectException) {
                device.waitForIdle()
            }
        }
        showDownloadOnce(force)
    }

    private fun showDownloadOnce(force: Boolean) {
        // the picker reopens where it was last used, maybe a folder inside Download: the last crumb counts
        val crumbs = device.findObjects(By.res("$DOCS:id/breadcrumb_text")).mapNotNull {
            runCatching { it.visibleBounds.left to it.text }.getOrNull()
        }
        val inDownload = crumbs.maxByOrNull { it.first }?.second == "Download"
        if (inDownload && !force) return
        // the roots drawer: "Show roots" button in the toolbar
        device.findObject(By.desc("Show roots"))?.click()
        waitObj(By.text("Downloads"), what = "Downloads root").click()
        device.waitForIdle()
    }

    fun put(name: String, bytes: ByteArray): String {
        val b64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
        Shell.run("mkdir -p $DIR; echo '$b64' | base64 -d > $DIR/$name")
        return "$DIR/$name"
    }

    fun put(name: String, text: String) = put(name, text.toByteArray())

    fun read(path: String): ByteArray {
        val b64 = Shell.run("base64 -w 0 '$path' 2>/dev/null").trim()
        return if (b64.isEmpty()) ByteArray(0) else Base64.decode(b64, Base64.DEFAULT)
    }

    fun readText(path: String) = read(path).decodeToString()

    fun exists(path: String) = Shell.run("[ -f '$path' ] && echo yes").trim() == "yes"

    fun remove(path: String) = Shell.run("rm -rf '$path'")

    fun list(dir: String): List<String> = Shell.run("ls -1 '$dir' 2>/dev/null").lines().filter { it.isNotBlank() }
}

/** The notification shade. */
object Shade {
    fun open() {
        device.openNotification()
        device.wait(Until.hasObject(By.pkg("com.android.systemui")), 5000)
    }

    fun close() {
        device.pressBack()
        device.waitForIdle()
    }

    /** The notification whose title is [title] (expanded so its actions show). */
    fun find(title: String, timeoutMs: Long = 8000): UiObject2? = device.wait(Until.findObject(By.text(title)), timeoutMs)

    fun has(title: String, timeoutMs: Long = 3000) = find(title, timeoutMs) != null

    private fun row(title: String) =
        device.wait(Until.findObject(By.res("com.android.systemui:id/expandableNotificationRow").hasDescendant(By.text(title))), 8000)

    /** The action buttons of the notification titled [title] (expanded first: silent notifications start collapsed). */
    fun actions(title: String): List<String> {
        val r = row(title) ?: return emptyList()
        if (!r.hasObject(By.res("android:id/actions"))) {
            r.findObject(By.res("android:id/expand_button"))?.click()
            device.wait(Until.hasObject(By.res("android:id/actions")), 3000)
        }
        val again = row(title) ?: return emptyList()
        return again.findObject(By.res("android:id/actions"))?.children?.mapNotNull { it.text } ?: emptyList()
    }

    /** Taps the action button [action] of the notification titled [title]. */
    fun action(title: String, action: String) {
        val names = actions(title)
        assertNotNull("notification \"$title\"", row(title))
        val btn = row(title)!!.findObject(By.res("android:id/actions"))?.children?.firstOrNull { it.text.equals(action, true) }
        assertNotNull("action \"$action\" of \"$title\" (has $names)", btn)
        btn!!.click()
    }

    /** Taps the notification body. */
    fun tap(title: String) {
        row(title)!!.findObject(By.text(title)).click()
    }
}
