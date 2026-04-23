package labs.mindburn.helm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * SchemaValidator — post-deserialization JSON Schema constraint validation
 * for the Java SDK (MIN-20).
 *
 * Why this exists:
 *
 * The generated {@link TypesGen} class contains several notes explaining that
 * discriminated-union matching does not enforce full JSON Schema constraints.
 * The code generator emits deserialization logic but skips schema-level
 * constraints (min/max, enum membership, regex pattern, required fields)
 * during {@code oneOf} matching. This means a malformed payload can
 * deserialize to the wrong variant without error.
 *
 * This class provides the missing validation as a separate utility that SDK
 * consumers call after {@code TypesGen.parseXxx(json)} returns. It does NOT
 * modify the generated file (which would be overwritten by the next
 * {@code make codegen} run).
 *
 * Usage:
 * <pre>{@code
 *   Map<String, Object> ticket = parseJsonToMap(jsonString);
 *   List<String> errors = SchemaValidator.validateIntentTicket(ticket);
 *   if (!errors.isEmpty()) {
 *       throw new IllegalArgumentException("Invalid intent: " + errors);
 *   }
 * }</pre>
 *
 * Design: every validator returns {@code List<String>} of human-readable
 * error messages. Empty list means valid. Callers decide whether to throw,
 * log, or return. No exceptions thrown from this class.
 */
public final class SchemaValidator {

    // ── Enum whitelists from protocols/json-schemas/ ──────────────

    private static final List<String> VALID_VERDICTS =
        List.of("ALLOW", "DENY", "REQUIRE_APPROVAL", "REQUIRE_EVIDENCE");

    private static final List<String> VALID_EFFECT_STATUSES =
        List.of("PENDING", "EXECUTED", "FAILED", "CANCELLED");

    // Canonical ticket_id / decision_id / effect_id format: "<prefix>_<hex>"
    private static final Pattern ID_PATTERN =
        Pattern.compile("^[a-z]+_[0-9a-f\\-]{8,}$");

    // Ed25519 signatures are base64-encoded 64 bytes → 86-88 chars (with or without padding)
    private static final Pattern SIG_PATTERN =
        Pattern.compile("^[A-Za-z0-9+/=]{86,88}$");

    // RFC 3339 timestamp prefix (lenient — full strict parsing left to Instant.parse)
    private static final Pattern TIMESTAMP_PATTERN =
        Pattern.compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}");

    private SchemaValidator() {
        // Utility class — no instances.
    }

    // ── Per-type validators ──────────────────────────────────────

    /**
     * Validate a parsed IntentTicket against its JSON Schema constraints.
     *
     * @param raw the deserialized ticket as a Map (generator-agnostic shape)
     * @return list of human-readable errors; empty when valid
     */
    public static List<String> validateIntentTicket(Map<String, Object> raw) {
        List<String> errors = new ArrayList<>();
        if (raw == null) {
            errors.add("IntentTicket is null");
            return errors;
        }
        requireNonEmpty(raw, "ticket_id", errors);
        requireMatches(raw, "ticket_id", ID_PATTERN, errors);
        requireNonEmpty(raw, "intent", errors);
        requireNonEmpty(raw, "created_at", errors);
        requireMatches(raw, "created_at", TIMESTAMP_PATTERN, errors);
        Object principalObj = raw.get("principal");
        if (principalObj == null) {
            errors.add("IntentTicket.principal is required");
        } else if (principalObj instanceof Map<?, ?> p) {
            @SuppressWarnings("unchecked")
            Map<String, Object> principal = (Map<String, Object>) p;
            requireNonEmpty(principal, "principal_id", errors);
            requireNonEmpty(principal, "principal_type", errors);
        }
        return errors;
    }

    /**
     * Validate a parsed DecisionRecord.
     */
    public static List<String> validateDecisionRecord(Map<String, Object> raw) {
        List<String> errors = new ArrayList<>();
        if (raw == null) {
            errors.add("DecisionRecord is null");
            return errors;
        }
        requireNonEmpty(raw, "decision_id", errors);
        requireMatches(raw, "decision_id", ID_PATTERN, errors);
        requireEnumMember(raw, "result", VALID_VERDICTS, errors);
        requireNonEmpty(raw, "timestamp", errors);
        requireMatches(raw, "timestamp", TIMESTAMP_PATTERN, errors);
        return errors;
    }

    /**
     * Validate a parsed EffectReceipt.
     */
    public static List<String> validateEffectReceipt(Map<String, Object> raw) {
        List<String> errors = new ArrayList<>();
        if (raw == null) {
            errors.add("EffectReceipt is null");
            return errors;
        }
        requireNonEmpty(raw, "receipt_id", errors);
        requireNonEmpty(raw, "decision_id", errors);
        requireNonEmpty(raw, "effect_id", errors);
        requireEnumMember(raw, "status", VALID_EFFECT_STATUSES, errors);
        requireNonEmpty(raw, "timestamp", errors);
        Object sig = raw.get("signature");
        if (sig instanceof String s && !SIG_PATTERN.matcher(s).matches()) {
            errors.add("EffectReceipt.signature does not match Ed25519 base64 shape");
        }
        return errors;
    }

    // ── Helpers (package-private for unit tests) ──────────────────

    static void requireNonEmpty(Map<String, Object> m, String field, List<String> errors) {
        Object v = m.get(field);
        if (v == null || (v instanceof String s && s.isEmpty())) {
            errors.add(field + " is required and must be non-empty");
        }
    }

    static void requireMatches(Map<String, Object> m, String field, Pattern p, List<String> errors) {
        Object v = m.get(field);
        if (v instanceof String s && !p.matcher(s).matches()) {
            errors.add(field + " does not match expected pattern: " + p.pattern());
        }
    }

    static void requireEnumMember(
        Map<String, Object> m,
        String field,
        List<String> allowed,
        List<String> errors
    ) {
        Object v = m.get(field);
        if (v == null) {
            errors.add(field + " is required");
            return;
        }
        if (v instanceof String s && !allowed.contains(s)) {
            errors.add(field + "=" + s + " is not one of " + allowed);
        }
    }
}
