/*
 * This file is part of the CVSS Calculator.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.cvss;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import static us.springett.cvss.Parser.requireNonNull;

/**
 * Calculates CVSSv3 scores and vector.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV3 implements Cvss {

    static final String VECTOR_PREFIX = "CVSS:3.0";

    protected static final double NO_VALUE = -1.0;

    protected static final double exploitabilityCoefficient = 8.22;

    protected static final double scopeCoefficient = 1.08;

    protected AttackVector av;

    protected AttackComplexity ac;

    protected PrivilegesRequired pr;

    protected UserInteraction ui;

    protected Scope s;

    protected Exploitability e = Exploitability.NOT_DEFINED;

    protected RemediationLevel rl = RemediationLevel.NOT_DEFINED;

    protected ReportConfidence rc = ReportConfidence.NOT_DEFINED;

    protected CIA c;

    protected CIA i;

    protected CIA a;

    public CvssV3 attackVector(AttackVector av) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 attackComplexity(AttackComplexity ac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 privilegesRequired(PrivilegesRequired pr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 userInteraction(UserInteraction ui) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 scope(Scope s) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 confidentiality(CIA c) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 integrity(CIA i) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 availability(CIA a) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 exploitability(Exploitability e) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 remediationLevel(RemediationLevel rl) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV3 reportConfidence(ReportConfidence rc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    static final class Parser implements us.springett.cvss.Parser<CvssV3> {

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
        public CvssV3 parseVector(final String vector) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AttackVector {

        NETWORK(0.85, 'N'), ADJACENT(0.62, 'A'), LOCAL(0.55, 'L'), PHYSICAL(0.2, 'P');

        protected final double weight;

        protected final char shorthand;

        AttackVector(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AttackVector fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AttackComplexity {

        LOW(0.77, 'L'), HIGH(0.44, 'H');

        protected final double weight;

        protected final char shorthand;

        AttackComplexity(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AttackComplexity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum PrivilegesRequired {

        NONE(0.85, 0.85, 'N'), LOW(0.62, 0.68, 'L'), HIGH(0.27, 0.5, 'H');

        protected final double weight;

        protected final double scopeChangedWeight;

        protected final char shorthand;

        PrivilegesRequired(double weight, double scopeChangedWeight, char shorthand) {
            this.weight = weight;
            this.scopeChangedWeight = scopeChangedWeight;
            this.shorthand = shorthand;
        }

        public static PrivilegesRequired fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum UserInteraction {

        NONE(0.85, 'N'), REQUIRED(0.62, 'R');

        protected final double weight;

        protected final char shorthand;

        UserInteraction(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static UserInteraction fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum Scope {

        UNCHANGED(6.42, 'U'), CHANGED(7.52, 'C');

        protected final double weight;

        protected final char shorthand;

        Scope(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static Scope fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Temporal
    public enum Exploitability {

        UNPROVEN(0.91, 'U'), POC(0.94, 'P'), FUNCTIONAL(0.97, 'F'), HIGH(1.0, 'H'), NOT_DEFINED(1.0, 'X');

        protected final double weight;

        protected final char shorthand;

        Exploitability(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static Exploitability fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum RemediationLevel {

        UNAVAILABLE(1.0, 'U'), WORKAROUND(0.97, 'W'), TEMPORARY(0.96, 'T'), OFFICIAL(0.95, 'O'), NOT_DEFINED(1.0, 'X');

        protected final double weight;

        protected final char shorthand;

        RemediationLevel(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static RemediationLevel fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ReportConfidence {

        UNKNOWN(0.92, 'U'), REASONABLE(0.96, 'R'), CONFIRMED(1.0, 'C'), NOT_DEFINED(1.0, 'X');

        protected final double weight;

        protected final char shorthand;

        ReportConfidence(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ReportConfidence fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // End-Temporal
    public enum CIA {

        NONE(0, 'N'), LOW(0.22, 'L'), HIGH(0.56, 'H');

        protected final double weight;

        protected final char shorthand;

        CIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static CIA fromString(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    /**
     * {@inheritDoc}
     */
    public Score calculateScore() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    private double roundUp1(double d) {
        return Math.ceil(d * 10) / 10;
    }

    protected double roundNearestTenth(double d) {
        throw new UnsupportedOperationException("STUB: not implemented");
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

    public AttackVector getAttackVector() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public AttackComplexity getAttackComplexity() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public PrivilegesRequired getPrivilegesRequired() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public UserInteraction getUserInteraction() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public Scope getScope() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public Exploitability getExploitability() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public RemediationLevel getRemediationLevel() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public ReportConfidence getReportConfidence() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CIA getConfidentiality() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CIA getIntegrity() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CIA getAvailability() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public String toString() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }
}
