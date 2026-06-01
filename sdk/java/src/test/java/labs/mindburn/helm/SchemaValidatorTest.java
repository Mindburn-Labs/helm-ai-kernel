package labs.mindburn.helm;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SchemaValidatorTest {
    @Test
    void validatesNullInputs() {
        assertEquals(List.of("IntentTicket is null"), SchemaValidator.validateIntentTicket(null));
        assertEquals(List.of("DecisionRecord is null"), SchemaValidator.validateDecisionRecord(null));
        assertEquals(List.of("EffectReceipt is null"), SchemaValidator.validateEffectReceipt(null));
    }

    @Test
    void validatesIntentTicketHappyAndErrorPaths() {
        Map<String, Object> principal = new HashMap<>();
        principal.put("principal_id", "principal_12345678");
        principal.put("principal_type", "agent");
        Map<String, Object> ticket = new HashMap<>();
        ticket.put("ticket_id", "ticket_12345678");
        ticket.put("intent", "read");
        ticket.put("created_at", "2026-01-01T00:00:00");
        ticket.put("principal", principal);
        assertTrue(SchemaValidator.validateIntentTicket(ticket).isEmpty());

        Map<String, Object> missingPrincipal = new HashMap<>(ticket);
        missingPrincipal.remove("principal");
        assertTrue(SchemaValidator.validateIntentTicket(missingPrincipal).contains("IntentTicket.principal is required"));

        Map<String, Object> invalidPrincipal = new HashMap<>(ticket);
        invalidPrincipal.put("principal", Map.of("principal_id", "", "principal_type", ""));
        List<String> errors = SchemaValidator.validateIntentTicket(invalidPrincipal);
        assertTrue(errors.contains("principal_id is required and must be non-empty"));
        assertTrue(errors.contains("principal_type is required and must be non-empty"));
    }

    @Test
    void validatesDecisionRecordBranches() {
        Map<String, Object> valid = new HashMap<>();
        valid.put("decision_id", "decision_12345678");
        valid.put("result", "ALLOW");
        valid.put("timestamp", "2026-01-01T00:00:00");
        assertTrue(SchemaValidator.validateDecisionRecord(valid).isEmpty());

        Map<String, Object> invalid = new HashMap<>();
        invalid.put("decision_id", "bad");
        invalid.put("result", "MAYBE");
        invalid.put("timestamp", "not-a-time");
        List<String> errors = SchemaValidator.validateDecisionRecord(invalid);
        assertEquals(3, errors.size());
        assertTrue(errors.get(0).startsWith("decision_id does not match expected pattern"));
        assertTrue(errors.get(1).startsWith("result=MAYBE is not one of"));
        assertTrue(errors.get(2).startsWith("timestamp does not match expected pattern"));

        assertTrue(SchemaValidator.validateDecisionRecord(new HashMap<>()).contains("result is required"));
    }

    @Test
    void validatesEffectReceiptBranches() {
        Map<String, Object> valid = new HashMap<>();
        valid.put("receipt_id", "receipt_12345678");
        valid.put("decision_id", "decision_12345678");
        valid.put("effect_id", "effect_12345678");
        valid.put("status", "EXECUTED");
        valid.put("timestamp", "2026-01-01T00:00:00Z");
        valid.put("signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assertTrue(SchemaValidator.validateEffectReceipt(valid).isEmpty());

        Map<String, Object> invalid = new HashMap<>();
        invalid.put("receipt_id", "");
        invalid.put("decision_id", "");
        invalid.put("effect_id", "");
        invalid.put("status", "BROKEN");
        invalid.put("timestamp", "");
        invalid.put("signature", "short");
        List<String> errors = SchemaValidator.validateEffectReceipt(invalid);
        assertFalse(errors.isEmpty());
        assertTrue(errors.stream().anyMatch(error -> error.contains("signature does not match")));
    }

    @Test
    void packageHelpersCoverAcceptedAndRejectedBranches() {
        List<String> errors = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("field", "value");
        SchemaValidator.requireNonEmpty(data, "field", errors);
        SchemaValidator.requireMatches(data, "field", Pattern.compile("^value$"), errors);
        SchemaValidator.requireEnumMember(data, "field", List.of("value"), errors);
        assertTrue(errors.isEmpty());

        data.put("field", "");
        SchemaValidator.requireNonEmpty(data, "field", errors);
        data.put("field", "other");
        SchemaValidator.requireMatches(data, "field", Pattern.compile("^value$"), errors);
        SchemaValidator.requireEnumMember(data, "field", List.of("value"), errors);
        assertEquals(3, errors.size());
    }
}
