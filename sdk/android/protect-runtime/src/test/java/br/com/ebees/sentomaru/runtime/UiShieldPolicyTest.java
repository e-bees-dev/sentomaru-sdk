package br.com.ebees.sentomaru.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

/** UIS-01 (G-10): which screens the shield touches and which calls each one gets, on the JVM. */
public class UiShieldPolicyTest {
    private static final String MAIN = "br.com.example.Main";
    private static final String PAY = "br.com.example.pay.PayActivity";

    private static final class Recorder implements UiShieldPolicy.Steps {
        final List<String> calls = new ArrayList<>();
        private final String failing;

        Recorder(String failing) { this.failing = failing; }

        private void note(String name) {
            if (name.equals(failing)) throw new SecurityException(name);
            calls.add(name);
        }

        @Override public void secureFlag() { note("secure"); }
        @Override public void recentsOff() { note("recents"); }
        @Override public void hideOverlay() { note("overlay"); }
        @Override public void filterObscuredTouches() { note("filter"); }
        @Override public void accessibilityDataSensitive() { note("a11y"); }
    }

    private static List<String> applied(UiShieldPolicy policy, String screen, int sdk, String failing) {
        Recorder r = new Recorder(failing);
        policy.apply(screen, sdk, r);
        return r.calls;
    }

    @Test public void aListedScreenGetsEveryCallItsApiLevelAllowsAndAnUnlistedOneNone() {
        UiShieldPolicy p = UiShieldPolicy.parse("listed_only", PAY + "," + MAIN, "true");
        assertNotNull(p);
        assertEquals(Arrays.asList("secure", "recents", "overlay", "filter", "a11y"), applied(p, PAY, 35, null));
        assertEquals(Arrays.asList("secure", "recents", "overlay", "filter"), applied(p, PAY, 33, null));
        assertEquals(Arrays.asList("secure", "overlay", "filter"), applied(p, PAY, 31, null));
        assertEquals(Arrays.asList("secure", "filter"), applied(p, PAY, 28, null));
        assertTrue(applied(p, "br.com.example.Other", 35, null).isEmpty());
        assertTrue("a prefix is not a listing", applied(p, PAY + "2", 35, null).isEmpty());
        assertTrue(applied(p, null, 35, null).isEmpty());
    }

    @Test public void theOverlayCallOnlyWhenTheProfileAsksForIt() {
        UiShieldPolicy p = UiShieldPolicy.parse("listed_only", MAIN, "false");
        assertEquals(Arrays.asList("secure", "recents", "filter", "a11y"), applied(p, MAIN, 35, null));
    }

    @Test public void allActivitiesMarksEveryScreen() {
        UiShieldPolicy p = UiShieldPolicy.parse("all_activities", "", "false");
        assertNotNull(p);
        assertTrue(p.marks("any.Screen"));
        assertEquals(Arrays.asList("secure", "recents", "filter", "a11y"), applied(p, "any.Screen", 35, null));
    }

    @Test public void oneRefusedCallNeverSkipsTheOthersNorThrows() {
        UiShieldPolicy p = UiShieldPolicy.parse("listed_only", MAIN, "true");
        for (String failing : new String[] {"secure", "recents", "overlay", "filter", "a11y"}) {
            List<String> done = applied(p, MAIN, 35, failing);
            assertEquals(failing, 4, done.size());
            assertFalse(failing, done.contains(failing));
        }
    }

    @Test public void anUnreadableConfigurationLeavesTheShieldOff() {
        for (String[] bad : new String[][] {
            {null, MAIN, "true"}, {"listed_only", null, "true"}, {"listed_only", MAIN, null},
            {"listed_only", "", "true"}, {"all_activities", MAIN, "true"}, {"everything", MAIN, "true"},
            {"listed_only", MAIN, "yes"}, {"listed_only", MAIN + ",", "true"}, {"listed_only", "," + MAIN, "true"},
            {"listed_only", MAIN + "," + MAIN, "true"}, {"listed_only", "NoPackage", "true"}, {"listed_only", "a..B", "true"},
            {"listed_only", "a.1B", "true"}, {"listed_only", "a.b c", "true"}, {"listed_only", "a.b.", "true"},
            {"listed_only", "a." + new String(new char[300]).replace('\0', 'x'), "true"},
        }) {
            assertNull(Arrays.toString(bad), UiShieldPolicy.parse(bad[0], bad[1], bad[2]));
        }
        StringBuilder many = new StringBuilder();
        for (int i = 0; i <= UiShieldPolicy.MAX_ACTIVITIES; i++) many.append(i == 0 ? "" : ",").append("a.A").append(i);
        assertNull(UiShieldPolicy.parse("listed_only", many.toString(), "true"));
        assertNotNull(UiShieldPolicy.parse("listed_only", many.substring(0, many.lastIndexOf(",")), "true"));
        assertNotNull("inner and Kotlin-style names", UiShieldPolicy.parse("listed_only", "a.b.Outer$Inner,a.b.étran", "false"));
    }

    /** G10-2: a boolean- or string-typed meta-data both turn the shield on; another type leaves it off. */
    @Test public void aTypedBooleanMetaDataIsReadLikeItsText() {
        UiShieldPolicy typed = UiShieldPolicy.parse(UiShieldPolicy.text("listed_only"), UiShieldPolicy.text(MAIN), UiShieldPolicy.text(Boolean.TRUE));
        assertNotNull(typed);
        assertTrue(typed.hideOverlayWindows);
        assertEquals("false", UiShieldPolicy.text(Boolean.FALSE));
        assertEquals("true", UiShieldPolicy.text("true"));
        assertNull(UiShieldPolicy.text(Integer.valueOf(1)));
        assertNull(UiShieldPolicy.text(null));
        assertNull(UiShieldPolicy.parse("listed_only", MAIN, UiShieldPolicy.text(Integer.valueOf(1))));
    }
}
