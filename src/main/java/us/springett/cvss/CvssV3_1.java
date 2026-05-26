package us.springett.cvss;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import static us.springett.cvss.Parser.requireNonNull;

public class CvssV3_1 extends CvssV3 {

    static final String VECTOR_PREFIX = "CVSS:3.1";

    /**
     * * Environmental Score Metric Group ***
     */
    protected ModifiedAttackVector mav = ModifiedAttackVector.NOT_DEFINED;

    protected ModifiedAttackComplexity mac = ModifiedAttackComplexity.NOT_DEFINED;

    protected ModifiedPrivilegesRequired mpr = ModifiedPrivilegesRequired.NOT_DEFINED;

    protected ModifiedUserInteraction mui = ModifiedUserInteraction.NOT_DEFINED;

    protected ModifiedScope ms = ModifiedScope.NOT_DEFINED;

    protected ModifiedCIA mc = ModifiedCIA.NOT_DEFINED;

    protected ModifiedCIA mi = ModifiedCIA.NOT_DEFINED;

    protected ModifiedCIA ma = ModifiedCIA.NOT_DEFINED;

    protected ConfidentialityRequirement cr = ConfidentialityRequirement.NOT_DEFINED;

    protected IntegrityRequirement ir = IntegrityRequirement.NOT_DEFINED;

    protected AvailabilityRequirement ar = AvailabilityRequirement.NOT_DEFINED;

    @Override
    public CvssV3_1 attackVector(AttackVector av) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 attackComplexity(AttackComplexity ac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 privilegesRequired(PrivilegesRequired pr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 userInteraction(UserInteraction ui) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 scope(Scope s) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 confidentiality(CIA c) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 integrity(CIA i) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 availability(CIA a) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 exploitability(Exploitability e) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 remediationLevel(RemediationLevel rl) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public CvssV3_1 reportConfidence(ReportConfidence rc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 confidentialityRequirement(ConfidentialityRequirement cr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 integrityRequirement(IntegrityRequirement ir) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 availabilityRequirement(AvailabilityRequirement ar) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedAttackVector(ModifiedAttackVector mav) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedAttackComplexity(ModifiedAttackComplexity mac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedPrivilegesRequired(ModifiedPrivilegesRequired mpr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedUserInteraction(ModifiedUserInteraction mui) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedScope(ModifiedScope ms) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedConfidentialityImpact(ModifiedCIA mc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedIntegrityImpact(ModifiedCIA mi) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3_1 modifiedAvailabilityImpact(ModifiedCIA ma) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * {@inheritDoc}
     */
    public Score calculateScore() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    private double roundUp1(double d) {
        int integerInput = (int) (d * 100000);
        if ((integerInput % 10000) == 0) {
            return integerInput / 100000.0;
        } else {
            return Math.floor((double) (integerInput / 10000) + 1) / 10.0;
        }
    }

    @Override
    public String getName() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    /**
     * {@inheritDoc}
     */
    public String getVector() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedAttackVector getModifiedAttackVector() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedAttackComplexity getModifiedAttackComplexity() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedPrivilegesRequired getModifiedPrivilegesRequired() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedUserInteraction getModifiedUserInteraction() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedScope getModifiedScope() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedCIA getModifiedConfidentialityImpact() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedCIA getModifiedIntegrityImpact() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ModifiedCIA getModifiedAvailabilityImpact() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ConfidentialityRequirement getConfidentialityRequirement() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public IntegrityRequirement getIntegrityRequirement() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public AvailabilityRequirement getAvailabilityRequirement() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public enum ConfidentialityRequirement {

        NOT_DEFINED(1.0, 'X'), LOW(0.5, 'L'), MEDIUM(1.0, 'M'), HIGH(1.5, 'H');

        protected final double weight;

        protected final char shorthand;

        ConfidentialityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ConfidentialityRequirement fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum IntegrityRequirement {

        NOT_DEFINED(1.0, 'X'), LOW(0.5, 'L'), MEDIUM(1.0, 'M'), HIGH(1.5, 'H');

        protected final double weight;

        protected final char shorthand;

        IntegrityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static IntegrityRequirement fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AvailabilityRequirement {

        NOT_DEFINED(1.0, 'X'), LOW(0.5, 'L'), MEDIUM(1.0, 'M'), HIGH(1.5, 'H');

        protected final double weight;

        protected final char shorthand;

        AvailabilityRequirement(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AvailabilityRequirement fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedAttackVector {

        NOT_DEFINED(0.0, 'X'), NETWORK(0.85, 'N'), ADJACENT(0.62, 'A'), LOCAL(0.55, 'L'), PHYSICAL(0.2, 'P');

        protected final double weight;

        protected final char shorthand;

        ModifiedAttackVector(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackVector fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedAttackComplexity {

        NOT_DEFINED(0.0, 'X'), LOW(0.77, 'L'), HIGH(0.44, 'H');

        protected final double weight;

        protected final char shorthand;

        ModifiedAttackComplexity(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedAttackComplexity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedPrivilegesRequired {

        NOT_DEFINED(0.0, 0.0, 'X'), NONE(0.85, 0.85, 'N'), LOW(0.62, 0.68, 'L'), HIGH(0.27, 0.5, 'H');

        protected final double weight;

        protected final double scopeChangedWeight;

        protected final char shorthand;

        ModifiedPrivilegesRequired(double weight, double scopeChangedWeight, char shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }

        public static ModifiedPrivilegesRequired fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedUserInteraction {

        NOT_DEFINED(0.0, 'X'), NONE(0.85, 'N'), REQUIRED(0.62, 'R');

        protected final double weight;

        protected final char shorthand;

        ModifiedUserInteraction(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedUserInteraction fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedScope {

        NOT_DEFINED(0.0, 'X'), UNCHANGED(6.42, 'U'), CHANGED(7.52, 'C');

        protected final double weight;

        protected final char shorthand;

        ModifiedScope(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedScope fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedCIA {

        NOT_DEFINED(0.0, 'X'), NONE(0.0, 'N'), LOW(0.22, 'L'), HIGH(0.56, 'H');

        protected final double weight;

        protected final char shorthand;

        ModifiedCIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ModifiedCIA fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    static final class Parser implements us.springett.cvss.Parser<CvssV3_1> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList(// Base metrics.
        "AV", // Base metrics.
        "AC", // Base metrics.
        "PR", // Base metrics.
        "UI", // Base metrics.
        "S", // Base metrics.
        "C", // Base metrics.
        "I", // Base metrics.
        "A");

        @Override
        public CvssV3_1 parseVector(final String vector) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }
}
