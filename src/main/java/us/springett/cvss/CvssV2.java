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
 * Calculates CVSSv2 scores and vector.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class CvssV2 implements Cvss {

    private static final double NO_VALUE = -1.0;

    private AttackVector av;

    private AttackComplexity ac;

    private Authentication au;

    private Exploitability e = Exploitability.NOT_DEFINED;

    private RemediationLevel rl = RemediationLevel.NOT_DEFINED;

    private ReportConfidence rc = ReportConfidence.NOT_DEFINED;

    private CIA c;

    private CIA i;

    private CIA a;

    public CvssV2 attackVector(AttackVector av) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 attackComplexity(AttackComplexity ac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 authentication(Authentication au) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 confidentiality(CIA c) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 integrity(CIA i) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 availability(CIA a) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 exploitability(Exploitability e) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 remediationLevel(RemediationLevel rl) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV2 reportConfidence(ReportConfidence rc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public enum AttackVector {

        NETWORK(1.0, 'N'), ADJACENT(0.646, 'A'), LOCAL(0.395, 'L');

        private final double weight;

        private final char shorthand;

        AttackVector(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AttackVector fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AttackComplexity {

        LOW(0.71, 'L'), MEDIUM(0.61, 'M'), HIGH(0.35, 'H');

        private final double weight;

        private final char shorthand;

        AttackComplexity(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static AttackComplexity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum Authentication {

        NONE(0.704, 'N'), SINGLE(0.56, 'S'), MULTIPLE(0.45, 'M');

        private final double weight;

        private final char shorthand;

        Authentication(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static Authentication fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Temporal
    public enum Exploitability {

        UNPROVEN(0.85, "U"), POC(0.9, "POC"), FUNCTIONAL(0.95, "F"), HIGH(1.0, "H"), NOT_DEFINED(1.0, "ND");

        private final double weight;

        private final String shorthand;

        Exploitability(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static Exploitability fromString(String text) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum RemediationLevel {

        UNAVAILABLE(1.0, "U"), WORKAROUND(0.95, "W"), TEMPORARY(0.90, "TF"), OFFICIAL(0.87, "OF"), NOT_DEFINED(1.0, "ND");

        private final double weight;

        private final String shorthand;

        RemediationLevel(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static RemediationLevel fromString(String text) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ReportConfidence {

        UNCONFIRMED(0.90, "UC"), UNCORROBORATED(0.95, "UR"), CONFIRMED(1.0, "C"), NOT_DEFINED(1.0, "ND");

        private final double weight;

        private final String shorthand;

        ReportConfidence(double weight, String shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static ReportConfidence fromString(String text) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // End-Temporal
    public enum CIA {

        NONE(0.0, 'N'), PARTIAL(0.275, 'P'), COMPLETE(0.660, 'C');

        private final double weight;

        private final char shorthand;

        CIA(double weight, char shorthand) {
            this.weight = weight;
            this.shorthand = shorthand;
        }

        public static CIA fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    static final class Parser implements us.springett.cvss.Parser<CvssV2> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList(// Base metrics.
        "AV", // Base metrics.
        "AC", // Base metrics.
        "Au", // Base metrics.
        "C", // Base metrics.
        "I", // Base metrics.
        "A");

        @Override
        public CvssV2 parseVector(String vector) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    /**
     * {@inheritDoc}
     */
    public Score calculateScore() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    private double f(double impact) {
        return (impact == 0) ? 0 : 1.176;
    }

    private double roundNearestTenth(double d) {
        return Math.round(d * 10.0) / 10.0;
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

    public Authentication getAuthentication() {
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
