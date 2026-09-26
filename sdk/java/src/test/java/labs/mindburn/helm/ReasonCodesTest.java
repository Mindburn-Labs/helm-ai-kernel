package labs.mindburn.helm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ReasonCodesTest {
    @Test
    void namesEveryRegistryCodeAsItsWireString() {
        assertEquals(110, ReasonCodes.ALL.size());
        assertEquals("EMERGENCY_STOP_FENCED", ReasonCodes.EMERGENCY_STOP_FENCED);
        assertTrue(ReasonCodes.isRegistered(ReasonCodes.EMERGENCY_STOP_FENCED));
        assertFalse(ReasonCodes.isRegistered("NOT_A_REGISTERED_CODE"));
    }
}
