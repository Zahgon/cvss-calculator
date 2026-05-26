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
 * Calculates CVSSv4.0 scores and vector.
 *
 * @author Jeremy Long
 * @since 1.5.0
 */
public class CvssV4 implements Cvss {

    static final String VECTOR_PREFIX = "CVSS:4.0";

    // Base Metrics - Exploitability
    protected AttackVector av;

    protected AttackComplexity ac;

    protected AttackRequirements at;

    protected PrivilegesRequired pr;

    protected UserInteraction ui;

    // Base Metrics - Vulnerable System Impact
    protected Impact vc;

    protected Impact vi;

    protected Impact va;

    // Base Metrics - Subsequent System Impact
    protected Impact sc;

    protected Impact si;

    protected Impact sa;

    // Threat Metrics
    protected ExploitMaturity e = ExploitMaturity.NOT_DEFINED;

    // Environmental Metrics - Security Requirements
    protected SecurityRequirement cr = SecurityRequirement.NOT_DEFINED;

    protected SecurityRequirement ir = SecurityRequirement.NOT_DEFINED;

    protected SecurityRequirement ar = SecurityRequirement.NOT_DEFINED;

    // Environmental Metrics - Modified Base
    protected ModifiedAttackVector mav = ModifiedAttackVector.NOT_DEFINED;

    protected ModifiedAttackComplexity mac = ModifiedAttackComplexity.NOT_DEFINED;

    protected ModifiedAttackRequirements mat = ModifiedAttackRequirements.NOT_DEFINED;

    protected ModifiedPrivilegesRequired mpr = ModifiedPrivilegesRequired.NOT_DEFINED;

    protected ModifiedUserInteraction mui = ModifiedUserInteraction.NOT_DEFINED;

    protected ModifiedImpact mvc = ModifiedImpact.NOT_DEFINED;

    protected ModifiedImpact mvi = ModifiedImpact.NOT_DEFINED;

    protected ModifiedImpact mva = ModifiedImpact.NOT_DEFINED;

    protected ModifiedSubsequentImpact msc = ModifiedSubsequentImpact.NOT_DEFINED;

    protected ModifiedSubsequentImpact msi = ModifiedSubsequentImpact.NOT_DEFINED;

    protected ModifiedSubsequentImpact msa = ModifiedSubsequentImpact.NOT_DEFINED;

    // Supplemental Metrics
    protected Safety s = Safety.NOT_DEFINED;

    protected Automatable au = Automatable.NOT_DEFINED;

    protected Recovery r = Recovery.NOT_DEFINED;

    protected ValueDensity v = ValueDensity.NOT_DEFINED;

    protected VulnerabilityResponseEffort re = VulnerabilityResponseEffort.NOT_DEFINED;

    protected ProviderUrgency u = ProviderUrgency.NOT_DEFINED;

    // Fluent setters for Base Metrics - Exploitability
    public CvssV4 attackVector(AttackVector av) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 attackComplexity(AttackComplexity ac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 attackRequirements(AttackRequirements at) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 privilegesRequired(PrivilegesRequired pr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 userInteraction(UserInteraction ui) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Base Metrics - Vulnerable System Impact
    public CvssV4 confidentialityImpact(Impact vc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 integrityImpact(Impact vi) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 availabilityImpact(Impact va) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Base Metrics - Subsequent System Impact
    public CvssV4 subsequentConfidentiality(Impact sc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 subsequentIntegrity(Impact si) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 subsequentAvailability(Impact sa) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Threat Metrics
    public CvssV4 exploitMaturity(ExploitMaturity e) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Environmental Metrics - Security Requirements
    public CvssV4 confidentialityRequirement(SecurityRequirement cr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 integrityRequirement(SecurityRequirement ir) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 availabilityRequirement(SecurityRequirement ar) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Environmental Metrics - Modified Base
    public CvssV4 modifiedAttackVector(ModifiedAttackVector mav) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedAttackComplexity(ModifiedAttackComplexity mac) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedAttackRequirements(ModifiedAttackRequirements mat) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedPrivilegesRequired(ModifiedPrivilegesRequired mpr) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedUserInteraction(ModifiedUserInteraction mui) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedConfidentialityImpact(ModifiedImpact mvc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedIntegrityImpact(ModifiedImpact mvi) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedAvailabilityImpact(ModifiedImpact mva) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedSubsequentConfidentiality(ModifiedSubsequentImpact msc) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedSubsequentIntegrity(ModifiedSubsequentImpact msi) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 modifiedSubsequentAvailability(ModifiedSubsequentImpact msa) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    // Fluent setters for Supplemental Metrics
    public CvssV4 safety(Safety s) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 automatable(Automatable au) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 recovery(Recovery r) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 valueDensity(ValueDensity v) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 vulnerabilityResponseEffort(VulnerabilityResponseEffort re) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    public CvssV4 providerUrgency(ProviderUrgency u) {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public String getName() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public String getVector() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    @Override
    public Score calculateScore() {
        throw new UnsupportedOperationException("STUB: not implemented");
    }

    private String deriveMacroVector() {
        int eq1 = deriveEQ1();
        int eq2 = deriveEQ2();
        int eq3 = deriveEQ3();
        int eq4 = deriveEQ4();
        int eq5 = deriveEQ5();
        int eq6 = deriveEQ6();
        return String.valueOf(eq1) + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    private int deriveEQ1() {
        // EQ1: Attack Complexity and Exploitability
        // Use modified metrics if defined, otherwise use base metrics
        // 0: AV=N AND PR=N AND UI=N
        // 1: (AV=N OR PR=N OR UI=N) AND NOT(all three) AND AV!=P
        // 2: AV=P OR NOT(any of AV,PR,UI are N)
        AttackVector effectiveAV = (mav != ModifiedAttackVector.NOT_DEFINED) ? convertModifiedAV(mav) : av;
        PrivilegesRequired effectivePR = (mpr != ModifiedPrivilegesRequired.NOT_DEFINED) ? convertModifiedPR(mpr) : pr;
        UserInteraction effectiveUI = (mui != ModifiedUserInteraction.NOT_DEFINED) ? convertModifiedUI(mui) : ui;
        boolean avIsN = (effectiveAV == AttackVector.NETWORK);
        boolean prIsN = (effectivePR == PrivilegesRequired.NONE);
        boolean uiIsN = (effectiveUI == UserInteraction.NONE);
        if (avIsN && prIsN && uiIsN) {
            return 0;
        } else if ((avIsN || prIsN || uiIsN) && effectiveAV != AttackVector.PHYSICAL) {
            return 1;
        } else {
            return 2;
        }
    }

    private int deriveEQ2() {
        // EQ2: Attack Complexity and Requirements
        // Use modified metrics if defined
        // 0: AC=L AND AT=N
        // 1: Otherwise
        AttackComplexity effectiveAC = (mac != ModifiedAttackComplexity.NOT_DEFINED) ? convertModifiedAC(mac) : ac;
        AttackRequirements effectiveAT = (mat != ModifiedAttackRequirements.NOT_DEFINED) ? convertModifiedAT(mat) : at;
        if (effectiveAC == AttackComplexity.LOW && effectiveAT == AttackRequirements.NONE) {
            return 0;
        } else {
            return 1;
        }
    }

    private int deriveEQ3() {
        // EQ3: Vulnerable System Impact
        // Use modified metrics if defined, with security requirements
        // 0: VC=H AND VI=H
        // 1: NOT(VC=H AND VI=H) AND (VC=H OR VI=H OR VA=H)
        // 2: NOT(VC=H OR VI=H OR VA=H)
        Impact effectiveVC = (mvc != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvc) : vc;
        Impact effectiveVI = (mvi != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvi) : vi;
        Impact effectiveVA = (mva != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mva) : va;
        boolean vcIsH = (effectiveVC == Impact.HIGH);
        boolean viIsH = (effectiveVI == Impact.HIGH);
        boolean vaIsH = (effectiveVA == Impact.HIGH);
        if (vcIsH && viIsH) {
            return 0;
        } else if (vcIsH || viIsH || vaIsH) {
            return 1;
        } else {
            return 2;
        }
    }

    private int deriveEQ4() {
        // EQ4: Subsequent System Impact
        // Use modified subsequent metrics if defined
        // 0: MSI=S OR MSA=S (Safety impact)
        // 1: NOT(MSI=S OR MSA=S) AND (SC=H OR SI=H OR SA=H)
        // 2: NOT(MSI=S OR MSA=S) AND NOT(SC=H OR SI=H OR SA=H)
        boolean msiIsS = (msi == ModifiedSubsequentImpact.SAFETY);
        boolean msaIsS = (msa == ModifiedSubsequentImpact.SAFETY);
        // Use modified subsequent impacts if defined
        Impact effectiveSC = (msc != ModifiedSubsequentImpact.NOT_DEFINED && msc != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msc) : sc;
        Impact effectiveSI = (msi != ModifiedSubsequentImpact.NOT_DEFINED && msi != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msi) : si;
        Impact effectiveSA = (msa != ModifiedSubsequentImpact.NOT_DEFINED && msa != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msa) : sa;
        boolean scIsH = (effectiveSC == Impact.HIGH);
        boolean siIsH = (effectiveSI == Impact.HIGH);
        boolean saIsH = (effectiveSA == Impact.HIGH);
        if (msiIsS || msaIsS) {
            return 0;
        } else if (scIsH || siIsH || saIsH) {
            return 1;
        } else {
            return 2;
        }
    }

    private int deriveEQ5() {
        // EQ5: Exploit Maturity
        // 0: E=A (Attacked) or E=X (Not Defined, defaults to Attacked)
        // 1: E=P (POC)
        // 2: E=U (Unreported)
        if (e == ExploitMaturity.ATTACKED || e == ExploitMaturity.NOT_DEFINED) {
            return 0;
        } else if (e == ExploitMaturity.POC) {
            return 1;
        } else {
            return 2;
        }
    }

    private int deriveEQ6() {
        // EQ6: Environmental Impact
        // Consider security requirements with effective impacts
        // CR/IR/AR default to HIGH when NOT_DEFINED
        // 0: (CR=H AND VC=H) OR (IR=H AND VI=H) OR (AR=H AND VA=H)
        // 1: Otherwise
        Impact effectiveVC = (mvc != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvc) : vc;
        Impact effectiveVI = (mvi != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvi) : vi;
        Impact effectiveVA = (mva != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mva) : va;
        // CR/IR/AR default to HIGH when NOT_DEFINED
        boolean effectiveCR_High = (cr == SecurityRequirement.HIGH || cr == SecurityRequirement.NOT_DEFINED);
        boolean effectiveIR_High = (ir == SecurityRequirement.HIGH || ir == SecurityRequirement.NOT_DEFINED);
        boolean effectiveAR_High = (ar == SecurityRequirement.HIGH || ar == SecurityRequirement.NOT_DEFINED);
        boolean crAndVc = (effectiveCR_High && effectiveVC == Impact.HIGH);
        boolean irAndVi = (effectiveIR_High && effectiveVI == Impact.HIGH);
        boolean arAndVa = (effectiveAR_High && effectiveVA == Impact.HIGH);
        if (crAndVc || irAndVi || arAndVa) {
            return 0;
        } else {
            return 1;
        }
    }

    // Helper methods to convert modified metrics to base metric equivalents
    private AttackVector convertModifiedAV(ModifiedAttackVector mav) {
        switch(mav) {
            case NETWORK:
                return AttackVector.NETWORK;
            case ADJACENT:
                return AttackVector.ADJACENT;
            case LOCAL:
                return AttackVector.LOCAL;
            case PHYSICAL:
                return AttackVector.PHYSICAL;
            default:
                return av;
        }
    }

    private PrivilegesRequired convertModifiedPR(ModifiedPrivilegesRequired mpr) {
        switch(mpr) {
            case NONE:
                return PrivilegesRequired.NONE;
            case LOW:
                return PrivilegesRequired.LOW;
            case HIGH:
                return PrivilegesRequired.HIGH;
            default:
                return pr;
        }
    }

    private UserInteraction convertModifiedUI(ModifiedUserInteraction mui) {
        switch(mui) {
            case NONE:
                return UserInteraction.NONE;
            case PASSIVE:
                return UserInteraction.PASSIVE;
            case ACTIVE:
                return UserInteraction.ACTIVE;
            default:
                return ui;
        }
    }

    private AttackComplexity convertModifiedAC(ModifiedAttackComplexity mac) {
        switch(mac) {
            case LOW:
                return AttackComplexity.LOW;
            case HIGH:
                return AttackComplexity.HIGH;
            default:
                return ac;
        }
    }

    private AttackRequirements convertModifiedAT(ModifiedAttackRequirements mat) {
        switch(mat) {
            case NONE:
                return AttackRequirements.NONE;
            case PRESENT:
                return AttackRequirements.PRESENT;
            default:
                return at;
        }
    }

    private Impact convertModifiedImpact(ModifiedImpact mi) {
        switch(mi) {
            case HIGH:
                return Impact.HIGH;
            case LOW:
                return Impact.LOW;
            case NONE:
            default:
                return Impact.NONE;
        }
    }

    private Impact convertModifiedSubsequentImpact(ModifiedSubsequentImpact msi) {
        switch(msi) {
            case HIGH:
                return Impact.HIGH;
            case LOW:
                return Impact.LOW;
            case NEGLIGIBLE:
            default:
                return Impact.NONE;
        }
    }

    private double interpolate(String macroVector, double baseScore) {
        // Parse MacroVector into EQ components
        int eq1 = Character.getNumericValue(macroVector.charAt(0));
        int eq2 = Character.getNumericValue(macroVector.charAt(1));
        int eq3 = Character.getNumericValue(macroVector.charAt(2));
        int eq4 = Character.getNumericValue(macroVector.charAt(3));
        int eq5 = Character.getNumericValue(macroVector.charAt(4));
        int eq6 = Character.getNumericValue(macroVector.charAt(5));
        // Calculate severity distances and available distances for each EQ
        double meanDistance = 0.0;
        int count = 0;
        // EQ1
        if (eq1 < 2) {
            String lowerMV = (eq1 + 1) + macroVector.substring(1);
            if (CvssV4Lookup.contains(lowerMV)) {
                double availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                double severityDistance = calculateEQ1SeverityDistance();
                int maxSeverity = CvssV4MaxSeverity.getMaxSeverity("eq1", eq1);
                double proportion = severityDistance / (maxSeverity * 0.1);
                meanDistance += availableDistance * proportion;
                count++;
            }
        }
        // EQ2
        if (eq2 < 1) {
            String lowerMV = macroVector.substring(0, 1) + (eq2 + 1) + macroVector.substring(2);
            if (CvssV4Lookup.contains(lowerMV)) {
                double availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                double severityDistance = calculateEQ2SeverityDistance();
                int maxSeverity = CvssV4MaxSeverity.getMaxSeverity("eq2", eq2);
                double proportion = severityDistance / (maxSeverity * 0.1);
                meanDistance += availableDistance * proportion;
                count++;
            }
        }
        // EQ3 and EQ6 (coupled dimension - handle specially)
        if (eq3 < 2 || eq6 < 1) {
            String lowerMV = null;
            double availableDistance = 0;
            // Handle the coupled EQ3/EQ6 dimension per official algorithm
            if (eq3 == 0 && eq6 == 0) {
                // Two possible paths: increase eq3 or eq6
                String lowerMV3 = macroVector.substring(0, 2) + (eq3 + 1) + macroVector.substring(3);
                String lowerMV6 = macroVector.substring(0, 5) + (eq6 + 1);
                // Use the path with the higher score (less severe)
                if (CvssV4Lookup.contains(lowerMV3) && CvssV4Lookup.contains(lowerMV6)) {
                    double score3 = CvssV4Lookup.lookupScore(lowerMV3);
                    double score6 = CvssV4Lookup.lookupScore(lowerMV6);
                    lowerMV = (score3 > score6) ? lowerMV3 : lowerMV6;
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                } else if (CvssV4Lookup.contains(lowerMV3)) {
                    lowerMV = lowerMV3;
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV3);
                } else if (CvssV4Lookup.contains(lowerMV6)) {
                    lowerMV = lowerMV6;
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV6);
                }
            } else if (eq3 == 1 && eq6 == 1) {
                // Lower is (eq3+1, eq6)
                lowerMV = macroVector.substring(0, 2) + (eq3 + 1) + macroVector.substring(3);
                if (CvssV4Lookup.contains(lowerMV)) {
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                }
            } else if (eq3 == 0 && eq6 == 1) {
                // Increase eq3
                lowerMV = macroVector.substring(0, 2) + (eq3 + 1) + macroVector.substring(3);
                if (CvssV4Lookup.contains(lowerMV)) {
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                }
            } else if (eq3 == 1 && eq6 == 0) {
                // Increase eq6
                lowerMV = macroVector.substring(0, 5) + (eq6 + 1);
                if (CvssV4Lookup.contains(lowerMV)) {
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                }
            } else if (eq3 < 2) {
                // Just increase eq3
                lowerMV = macroVector.substring(0, 2) + (eq3 + 1) + macroVector.substring(3);
                if (CvssV4Lookup.contains(lowerMV)) {
                    availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                }
            }
            if (lowerMV != null) {
                double severityDistance = calculateEQ3EQ6SeverityDistance();
                int maxSeverity = CvssV4MaxSeverity.getMaxSeverityEq3Eq6(eq3, eq6);
                double proportion = severityDistance / (maxSeverity * 0.1);
                meanDistance += availableDistance * proportion;
                count++;
            }
        }
        // EQ4
        if (eq4 < 2) {
            String lowerMV = macroVector.substring(0, 3) + (eq4 + 1) + macroVector.substring(4);
            if (CvssV4Lookup.contains(lowerMV)) {
                double availableDistance = baseScore - CvssV4Lookup.lookupScore(lowerMV);
                double severityDistance = calculateEQ4SeverityDistance();
                int maxSeverity = CvssV4MaxSeverity.getMaxSeverity("eq4", eq4);
                double proportion = severityDistance / (maxSeverity * 0.1);
                meanDistance += availableDistance * proportion;
                count++;
            }
        }
        // EQ5 - contributes 0 to severity distance but DOES count in denominator
        if (eq5 < 2) {
            String lowerMV = macroVector.substring(0, 4) + (eq5 + 1) + macroVector.substring(5);
            if (CvssV4Lookup.contains(lowerMV)) {
                // EQ5 proportion is always 0, so normalized distance is 0
                // But it still counts in the denominator
                meanDistance += 0.0;
                count++;
            }
        }
        if (count > 0) {
            meanDistance = meanDistance / count;
        }
        return baseScore - meanDistance;
    }

    private double calculateEQ1SeverityDistance() {
        AttackVector effectiveAV = (mav != ModifiedAttackVector.NOT_DEFINED) ? convertModifiedAV(mav) : av;
        PrivilegesRequired effectivePR = (mpr != ModifiedPrivilegesRequired.NOT_DEFINED) ? convertModifiedPR(mpr) : pr;
        UserInteraction effectiveUI = (mui != ModifiedUserInteraction.NOT_DEFINED) ? convertModifiedUI(mui) : ui;
        int eq1 = deriveEQ1();
        String[] maxVectors = CvssV4MaxComposed.getMaxVectorsForEQ1(eq1);
        if (maxVectors == null || maxVectors.length == 0) {
            return 0.0;
        }
        String dominantMax = selectDominantMaxVector(maxVectors, effectiveAV, effectivePR, effectiveUI);
        if (dominantMax == null) {
            return 0.0;
        }
        AttackVector maxAV = extractAVFromVector(dominantMax);
        PrivilegesRequired maxPR = extractPRFromVector(dominantMax);
        UserInteraction maxUI = extractUIFromVector(dominantMax);
        double currentAV = getAttackVectorLevel(effectiveAV);
        double currentPR = getPrivilegesRequiredLevel(effectivePR);
        double currentUI = getUserInteractionLevel(effectiveUI);
        double maxAVLevel = getAttackVectorLevel(maxAV);
        double maxPRLevel = getPrivilegesRequiredLevel(maxPR);
        double maxUILevel = getUserInteractionLevel(maxUI);
        return (currentAV - maxAVLevel) + (currentPR - maxPRLevel) + (currentUI - maxUILevel);
    }

    private double calculateEQ2SeverityDistance() {
        AttackComplexity effectiveAC = (mac != ModifiedAttackComplexity.NOT_DEFINED) ? convertModifiedAC(mac) : ac;
        AttackRequirements effectiveAT = (mat != ModifiedAttackRequirements.NOT_DEFINED) ? convertModifiedAT(mat) : at;
        int eq2 = deriveEQ2();
        String[] maxVectors = CvssV4MaxComposed.getMaxVectorsForEQ2(eq2);
        if (maxVectors == null || maxVectors.length == 0) {
            return 0.0;
        }
        String dominantMax = selectDominantMaxVectorEQ2(maxVectors, effectiveAC, effectiveAT);
        if (dominantMax == null) {
            return 0.0;
        }
        AttackComplexity maxAC = extractACFromVector(dominantMax);
        AttackRequirements maxAT = extractATFromVector(dominantMax);
        double currentAC = getAttackComplexityLevel(effectiveAC);
        double currentAT = getAttackRequirementsLevel(effectiveAT);
        double maxACLevel = getAttackComplexityLevel(maxAC);
        double maxATLevel = getAttackRequirementsLevel(maxAT);
        return (currentAC - maxACLevel) + (currentAT - maxATLevel);
    }

    private double calculateEQ3EQ6SeverityDistance() {
        Impact effectiveVC = (mvc != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvc) : vc;
        Impact effectiveVI = (mvi != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mvi) : vi;
        Impact effectiveVA = (mva != ModifiedImpact.NOT_DEFINED) ? convertModifiedImpact(mva) : va;
        SecurityRequirement effectiveCR = (cr != SecurityRequirement.NOT_DEFINED) ? cr : SecurityRequirement.HIGH;
        SecurityRequirement effectiveIR = (ir != SecurityRequirement.NOT_DEFINED) ? ir : SecurityRequirement.HIGH;
        SecurityRequirement effectiveAR = (ar != SecurityRequirement.NOT_DEFINED) ? ar : SecurityRequirement.HIGH;
        int eq3 = deriveEQ3();
        int eq6 = deriveEQ6();
        String[] maxVectors = CvssV4MaxComposed.getMaxVectorsForEQ3EQ6(eq3, eq6);
        if (maxVectors == null || maxVectors.length == 0) {
            return 0.0;
        }
        String dominantMax = selectDominantMaxVectorEQ3EQ6(maxVectors, effectiveVC, effectiveVI, effectiveVA, effectiveCR, effectiveIR, effectiveAR);
        if (dominantMax == null) {
            return 0.0;
        }
        Impact maxVC = extractVCFromVector(dominantMax);
        Impact maxVI = extractVIFromVector(dominantMax);
        Impact maxVA = extractVAFromVector(dominantMax);
        SecurityRequirement maxCR = extractCRFromVector(dominantMax);
        SecurityRequirement maxIR = extractIRFromVector(dominantMax);
        SecurityRequirement maxAR = extractARFromVector(dominantMax);
        double currentVC = getImpactLevel(effectiveVC);
        double currentVI = getImpactLevel(effectiveVI);
        double currentVA = getImpactLevel(effectiveVA);
        double currentCR = getSecurityRequirementLevel(effectiveCR);
        double currentIR = getSecurityRequirementLevel(effectiveIR);
        double currentAR = getSecurityRequirementLevel(effectiveAR);
        double maxVCLevel = getImpactLevel(maxVC);
        double maxVILevel = getImpactLevel(maxVI);
        double maxVALevel = getImpactLevel(maxVA);
        double maxCRLevel = getSecurityRequirementLevel(maxCR);
        double maxIRLevel = getSecurityRequirementLevel(maxIR);
        double maxARLevel = getSecurityRequirementLevel(maxAR);
        return (currentVC - maxVCLevel) + (currentVI - maxVILevel) + (currentVA - maxVALevel) + (currentCR - maxCRLevel) + (currentIR - maxIRLevel) + (currentAR - maxARLevel);
    }

    private double calculateEQ4SeverityDistance() {
        Impact effectiveSC = (msc != ModifiedSubsequentImpact.NOT_DEFINED && msc != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msc) : sc;
        Impact effectiveSI = (msi != ModifiedSubsequentImpact.NOT_DEFINED && msi != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msi) : si;
        Impact effectiveSA = (msa != ModifiedSubsequentImpact.NOT_DEFINED && msa != ModifiedSubsequentImpact.SAFETY) ? convertModifiedSubsequentImpact(msa) : sa;
        boolean msiIsSafety = (msi == ModifiedSubsequentImpact.SAFETY);
        boolean msaIsSafety = (msa == ModifiedSubsequentImpact.SAFETY);
        int eq4 = deriveEQ4();
        String[] maxVectors = CvssV4MaxComposed.getMaxVectorsForEQ4(eq4);
        if (maxVectors == null || maxVectors.length == 0) {
            return 0.0;
        }
        String dominantMax = selectDominantMaxVectorEQ4(maxVectors, effectiveSC, effectiveSI, effectiveSA, msiIsSafety, msaIsSafety);
        if (dominantMax == null) {
            return 0.0;
        }
        Impact maxSC = extractSCFromVector(dominantMax);
        boolean maxSIIsSafety = extractSISafetyFromVector(dominantMax);
        boolean maxSAIsSafety = extractSASafetyFromVector(dominantMax);
        Impact maxSI = maxSIIsSafety ? Impact.NONE : extractSIFromVector(dominantMax);
        Impact maxSA = maxSAIsSafety ? Impact.NONE : extractSAFromVector(dominantMax);
        double currentSC = getSubsequentImpactLevel(effectiveSC);
        double currentSI = msiIsSafety ? 0.0 : getSubsequentImpactLevel(effectiveSI);
        double currentSA = msaIsSafety ? 0.0 : getSubsequentImpactLevel(effectiveSA);
        double maxSCLevel = getSubsequentImpactLevel(maxSC);
        double maxSILevel = maxSIIsSafety ? 0.0 : getSubsequentImpactLevel(maxSI);
        double maxSALevel = maxSAIsSafety ? 0.0 : getSubsequentImpactLevel(maxSA);
        return (currentSC - maxSCLevel) + (currentSI - maxSILevel) + (currentSA - maxSALevel);
    }

    private double getAttackComplexityLevel(AttackComplexity ac) {
        if (Objects.requireNonNull(ac) == AttackComplexity.HIGH) {
            return 0.1;
        }
        // Default Or LOW
        return 0.0;
    }

    private double getAttackRequirementsLevel(AttackRequirements at) {
        if (Objects.requireNonNull(at) == AttackRequirements.PRESENT) {
            return 0.1;
        }
        // Default Or NONE
        return 0.0;
    }

    private double getAttackVectorLevel(AttackVector av) {
        switch(av) {
            case ADJACENT:
                return 0.1;
            case LOCAL:
                return 0.2;
            case PHYSICAL:
                return 0.3;
            case NETWORK:
            default:
                return 0.0;
        }
    }

    private double getPrivilegesRequiredLevel(PrivilegesRequired pr) {
        switch(pr) {
            case HIGH:
                return 0.2;
            case LOW:
                return 0.1;
            case NONE:
            default:
                return 0.0;
        }
    }

    private double getUserInteractionLevel(UserInteraction ui) {
        switch(ui) {
            case PASSIVE:
                return 0.1;
            case ACTIVE:
                return 0.2;
            case NONE:
            default:
                return 0.0;
        }
    }

    private double getImpactLevel(Impact impact) {
        switch(impact) {
            case NONE:
                return 0.2;
            case LOW:
                return 0.1;
            case HIGH:
            default:
                return 0.0;
        }
    }

    private double getSubsequentImpactLevel(Impact impact) {
        // Subsequent impacts use different levels: H=0.1, L=0.2, N=0.3
        switch(impact) {
            case HIGH:
                return 0.1;
            case LOW:
                return 0.2;
            case NONE:
            default:
                return 0.3;
        }
    }

    private double getSecurityRequirementLevel(SecurityRequirement req) {
        switch(req) {
            case LOW:
                return 0.2;
            case MEDIUM:
                return 0.1;
            case HIGH:
            // Default to HIGH per CVSS v4.0 spec
            case NOT_DEFINED:
            default:
                return 0.0;
        }
    }

    private String selectDominantMaxVector(String[] maxVectors, AttackVector currentAV, PrivilegesRequired currentPR, UserInteraction currentUI) {
        for (String vector : maxVectors) {
            AttackVector maxAV = extractAVFromVector(vector);
            PrivilegesRequired maxPR = extractPRFromVector(vector);
            UserInteraction maxUI = extractUIFromVector(vector);
            if (getAttackVectorLevel(maxAV) <= getAttackVectorLevel(currentAV) && getPrivilegesRequiredLevel(maxPR) <= getPrivilegesRequiredLevel(currentPR) && getUserInteractionLevel(maxUI) <= getUserInteractionLevel(currentUI)) {
                return vector;
            }
        }
        return maxVectors.length > 0 ? maxVectors[0] : null;
    }

    private String selectDominantMaxVectorEQ2(String[] maxVectors, AttackComplexity currentAC, AttackRequirements currentAT) {
        for (String vector : maxVectors) {
            AttackComplexity maxAC = extractACFromVector(vector);
            AttackRequirements maxAT = extractATFromVector(vector);
            if (getAttackComplexityLevel(maxAC) <= getAttackComplexityLevel(currentAC) && getAttackRequirementsLevel(maxAT) <= getAttackRequirementsLevel(currentAT)) {
                return vector;
            }
        }
        return maxVectors.length > 0 ? maxVectors[0] : null;
    }

    private String selectDominantMaxVectorEQ3EQ6(String[] maxVectors, Impact currentVC, Impact currentVI, Impact currentVA, SecurityRequirement currentCR, SecurityRequirement currentIR, SecurityRequirement currentAR) {
        for (String vector : maxVectors) {
            Impact maxVC = extractVCFromVector(vector);
            Impact maxVI = extractVIFromVector(vector);
            Impact maxVA = extractVAFromVector(vector);
            SecurityRequirement maxCR = extractCRFromVector(vector);
            SecurityRequirement maxIR = extractIRFromVector(vector);
            SecurityRequirement maxAR = extractARFromVector(vector);
            if (getImpactLevel(maxVC) <= getImpactLevel(currentVC) && getImpactLevel(maxVI) <= getImpactLevel(currentVI) && getImpactLevel(maxVA) <= getImpactLevel(currentVA) && getSecurityRequirementLevel(maxCR) <= getSecurityRequirementLevel(currentCR) && getSecurityRequirementLevel(maxIR) <= getSecurityRequirementLevel(currentIR) && getSecurityRequirementLevel(maxAR) <= getSecurityRequirementLevel(currentAR)) {
                return vector;
            }
        }
        return maxVectors.length > 0 ? maxVectors[0] : null;
    }

    private String selectDominantMaxVectorEQ4(String[] maxVectors, Impact currentSC, Impact currentSI, Impact currentSA, boolean currentSIIsSafety, boolean currentSAIsSafety) {
        for (String vector : maxVectors) {
            Impact maxSC = extractSCFromVector(vector);
            boolean maxSIIsSafety = extractSISafetyFromVector(vector);
            boolean maxSAIsSafety = extractSASafetyFromVector(vector);
            Impact maxSI = maxSIIsSafety ? Impact.NONE : extractSIFromVector(vector);
            Impact maxSA = maxSAIsSafety ? Impact.NONE : extractSAFromVector(vector);
            double maxSCLevel = getSubsequentImpactLevel(maxSC);
            double maxSILevel = maxSIIsSafety ? 0.0 : getSubsequentImpactLevel(maxSI);
            double maxSALevel = maxSAIsSafety ? 0.0 : getSubsequentImpactLevel(maxSA);
            double currentSCLevel = getSubsequentImpactLevel(currentSC);
            double currentSILevel = currentSIIsSafety ? 0.0 : getSubsequentImpactLevel(currentSI);
            double currentSALevel = currentSAIsSafety ? 0.0 : getSubsequentImpactLevel(currentSA);
            if (maxSCLevel <= currentSCLevel && maxSILevel <= currentSILevel && maxSALevel <= currentSALevel) {
                return vector;
            }
        }
        return maxVectors.length > 0 ? maxVectors[0] : null;
    }

    private AttackVector extractAVFromVector(String vector) {
        if (vector.contains("AV:N"))
            return AttackVector.NETWORK;
        if (vector.contains("AV:A"))
            return AttackVector.ADJACENT;
        if (vector.contains("AV:L"))
            return AttackVector.LOCAL;
        if (vector.contains("AV:P"))
            return AttackVector.PHYSICAL;
        return AttackVector.NETWORK;
    }

    private PrivilegesRequired extractPRFromVector(String vector) {
        if (vector.contains("PR:N"))
            return PrivilegesRequired.NONE;
        if (vector.contains("PR:L"))
            return PrivilegesRequired.LOW;
        if (vector.contains("PR:H"))
            return PrivilegesRequired.HIGH;
        return PrivilegesRequired.NONE;
    }

    private UserInteraction extractUIFromVector(String vector) {
        if (vector.contains("UI:N"))
            return UserInteraction.NONE;
        if (vector.contains("UI:P"))
            return UserInteraction.PASSIVE;
        if (vector.contains("UI:A"))
            return UserInteraction.ACTIVE;
        return UserInteraction.NONE;
    }

    private AttackComplexity extractACFromVector(String vector) {
        if (vector.contains("AC:L"))
            return AttackComplexity.LOW;
        if (vector.contains("AC:H"))
            return AttackComplexity.HIGH;
        return AttackComplexity.LOW;
    }

    private AttackRequirements extractATFromVector(String vector) {
        if (vector.contains("AT:N"))
            return AttackRequirements.NONE;
        if (vector.contains("AT:P"))
            return AttackRequirements.PRESENT;
        return AttackRequirements.NONE;
    }

    private Impact extractVCFromVector(String vector) {
        if (vector.contains("VC:H"))
            return Impact.HIGH;
        if (vector.contains("VC:L"))
            return Impact.LOW;
        //if (vector.contains("VC:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private Impact extractVIFromVector(String vector) {
        if (vector.contains("VI:H"))
            return Impact.HIGH;
        if (vector.contains("VI:L"))
            return Impact.LOW;
        //if (vector.contains("VI:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private Impact extractVAFromVector(String vector) {
        if (vector.contains("VA:H"))
            return Impact.HIGH;
        if (vector.contains("VA:L"))
            return Impact.LOW;
        //if (vector.contains("VA:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private SecurityRequirement extractCRFromVector(String vector) {
        if (vector.contains("CR:H"))
            return SecurityRequirement.HIGH;
        if (vector.contains("CR:M"))
            return SecurityRequirement.MEDIUM;
        if (vector.contains("CR:L"))
            return SecurityRequirement.LOW;
        return SecurityRequirement.HIGH;
    }

    private SecurityRequirement extractIRFromVector(String vector) {
        if (vector.contains("IR:H"))
            return SecurityRequirement.HIGH;
        if (vector.contains("IR:M"))
            return SecurityRequirement.MEDIUM;
        if (vector.contains("IR:L"))
            return SecurityRequirement.LOW;
        return SecurityRequirement.HIGH;
    }

    private SecurityRequirement extractARFromVector(String vector) {
        if (vector.contains("AR:H"))
            return SecurityRequirement.HIGH;
        if (vector.contains("AR:M"))
            return SecurityRequirement.MEDIUM;
        if (vector.contains("AR:L"))
            return SecurityRequirement.LOW;
        return SecurityRequirement.HIGH;
    }

    private Impact extractSCFromVector(String vector) {
        if (vector.contains("SC:H"))
            return Impact.HIGH;
        if (vector.contains("SC:L"))
            return Impact.LOW;
        //if (vector.contains("SC:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private Impact extractSIFromVector(String vector) {
        if (vector.contains("SI:H"))
            return Impact.HIGH;
        if (vector.contains("SI:L"))
            return Impact.LOW;
        //if (vector.contains("SI:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private Impact extractSAFromVector(String vector) {
        if (vector.contains("SA:H"))
            return Impact.HIGH;
        if (vector.contains("SA:L"))
            return Impact.LOW;
        //if (vector.contains("SA:N")) return Impact.NONE;
        return Impact.NONE;
    }

    private boolean extractSISafetyFromVector(String vector) {
        return vector.contains("SI:S");
    }

    private boolean extractSASafetyFromVector(String vector) {
        return vector.contains("SA:S");
    }

    static final class Parser implements us.springett.cvss.Parser<CvssV4> {

        private static final List<String> MANDATORY_METRICS = Arrays.asList("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA");

        @Override
        public CvssV4 parseVector(final String vector) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Base Metric Enums
    public enum AttackVector {

        NETWORK('N'), ADJACENT('A'), LOCAL('L'), PHYSICAL('P');

        private final char shorthand;

        AttackVector(char shorthand) {
            this.shorthand = shorthand;
        }

        public static AttackVector fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AttackComplexity {

        LOW('L'), HIGH('H');

        private final char shorthand;

        AttackComplexity(char shorthand) {
            this.shorthand = shorthand;
        }

        public static AttackComplexity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum AttackRequirements {

        NONE('N'), PRESENT('P');

        private final char shorthand;

        AttackRequirements(char shorthand) {
            this.shorthand = shorthand;
        }

        public static AttackRequirements fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum PrivilegesRequired {

        NONE('N'), LOW('L'), HIGH('H');

        private final char shorthand;

        PrivilegesRequired(char shorthand) {
            this.shorthand = shorthand;
        }

        public static PrivilegesRequired fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum UserInteraction {

        NONE('N'), PASSIVE('P'), ACTIVE('A');

        private final char shorthand;

        UserInteraction(char shorthand) {
            this.shorthand = shorthand;
        }

        public static UserInteraction fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum Impact {

        HIGH('H'), LOW('L'), NONE('N');

        private final char shorthand;

        Impact(char shorthand) {
            this.shorthand = shorthand;
        }

        public static Impact fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Threat Metric Enum
    public enum ExploitMaturity {

        NOT_DEFINED('X'), ATTACKED('A'), POC('P'), UNREPORTED('U');

        private final char shorthand;

        ExploitMaturity(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ExploitMaturity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Environmental Metric Enums
    public enum SecurityRequirement {

        NOT_DEFINED('X'), HIGH('H'), MEDIUM('M'), LOW('L');

        private final char shorthand;

        SecurityRequirement(char shorthand) {
            this.shorthand = shorthand;
        }

        public static SecurityRequirement fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedAttackVector {

        NOT_DEFINED('X'), NETWORK('N'), ADJACENT('A'), LOCAL('L'), PHYSICAL('P');

        private final char shorthand;

        ModifiedAttackVector(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedAttackVector fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedAttackComplexity {

        NOT_DEFINED('X'), LOW('L'), HIGH('H');

        private final char shorthand;

        ModifiedAttackComplexity(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedAttackComplexity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedAttackRequirements {

        NOT_DEFINED('X'), NONE('N'), PRESENT('P');

        private final char shorthand;

        ModifiedAttackRequirements(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedAttackRequirements fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedPrivilegesRequired {

        NOT_DEFINED('X'), NONE('N'), LOW('L'), HIGH('H');

        private final char shorthand;

        ModifiedPrivilegesRequired(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedPrivilegesRequired fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedUserInteraction {

        NOT_DEFINED('X'), NONE('N'), PASSIVE('P'), ACTIVE('A');

        private final char shorthand;

        ModifiedUserInteraction(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedUserInteraction fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedImpact {

        NOT_DEFINED('X'), HIGH('H'), LOW('L'), NONE('N');

        private final char shorthand;

        ModifiedImpact(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedImpact fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ModifiedSubsequentImpact {

        NOT_DEFINED('X'), SAFETY('S'), HIGH('H'), LOW('L'), NEGLIGIBLE('N');

        private final char shorthand;

        ModifiedSubsequentImpact(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ModifiedSubsequentImpact fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    // Supplemental Metric Enums
    public enum Safety {

        NOT_DEFINED('X'), NEGLIGIBLE('N'), PRESENT('P');

        private final char shorthand;

        Safety(char shorthand) {
            this.shorthand = shorthand;
        }

        public static Safety fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum Automatable {

        NOT_DEFINED('X'), NO('N'), YES('Y');

        private final char shorthand;

        Automatable(char shorthand) {
            this.shorthand = shorthand;
        }

        public static Automatable fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum Recovery {

        NOT_DEFINED('X'), AUTOMATIC('A'), USER('U'), IRRECOVERABLE('I');

        private final char shorthand;

        Recovery(char shorthand) {
            this.shorthand = shorthand;
        }

        public static Recovery fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ValueDensity {

        NOT_DEFINED('X'), DIFFUSE('D'), CONCENTRATED('C');

        private final char shorthand;

        ValueDensity(char shorthand) {
            this.shorthand = shorthand;
        }

        public static ValueDensity fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum VulnerabilityResponseEffort {

        NOT_DEFINED('X'), LOW('L'), MODERATE('M'), HIGH('H');

        private final char shorthand;

        VulnerabilityResponseEffort(char shorthand) {
            this.shorthand = shorthand;
        }

        public static VulnerabilityResponseEffort fromChar(char c) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }

    public enum ProviderUrgency {

        NOT_DEFINED("X"), CLEAR("Clear"), GREEN("Green"), AMBER("Amber"), RED("Red");

        private final String shorthand;

        ProviderUrgency(String shorthand) {
            this.shorthand = shorthand;
        }

        public static ProviderUrgency fromString(String s) {
            throw new UnsupportedOperationException("STUB: not implemented");
        }
    }
}
