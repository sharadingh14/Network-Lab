# 4 RESULTS

## 4.1 Data Quality

Table 4 shows that duplicate flows are the dominant data-quality issue in the six files: {{dup_pct}} % of all records are exact duplicates, and for some attack labels almost every record is a copy (FTP brute force: {{ftp_unique}} distinct records out of {{ftp_raw_fmt}}; DoS SlowHTTPTest: {{slowhttp_unique}} out of {{slowhttp_raw_fmt}}). These two labels are therefore nearly absent from the de-duplicated data, and any accuracy reported on them with a random split of the raw records would mostly measure memorisation of repeated flows. The remaining class imbalance is also large: in the evaluation portion, benign flows outnumber attacks, and the three web attacks together contribute only {{fam_web_n}} flows.

## 4.2 Detection Performance and Component Ablation

Table 5 reports the eleven detector configurations. The signature stage alone is very precise but misses about one attack flow in nine (recall {{sig_recall}} %, false-positive rate {{sig_far3}} %), because exact keys cannot cover attacks whose flows vary in size and duration. With all features, the classifiers alone reach mean F1-scores of {{m_MLP_all_f1}} % (MLP), {{m_XGBoost_all_f1}} % (XGBoost) and {{m_RandomForest_all_f1}} % (Random Forest), and the majority-vote ensemble {{ens_all_f1}} %. The ensemble is therefore better than the MLP and the Random Forest but not better than XGBoost alone, which also has the lowest false-positive rate ({{m_XGBoost_all_far3}} % against {{ens_all_far3}} %); a single XGBoost model would be a simpler and equally accurate choice for Phase 2 on this dataset. The full hybrid, in which flows not matched by a signature are passed to the ensemble, gives the best F1 with all features: {{hyb_all_f1_msd}} %, recall {{hyb_all_recall_msd}} %, false-positive rate {{hyb_all_far_msd}} % ({{hyb_all_fp}} false positives and {{hyb_all_fn}} false negatives on average), ROC-AUC {{hyb_all_roc_auc_msd}} % and PR-AUC {{hyb_all_pr_auc_msd}} %. The signature stage raises recall by catching attack flows that the ensemble misses, at the cost of a small number of additional false positives.

!table ablation

GA feature selection kept {{ga_nfeat_range}} of the {{n_feat}} features, depending on the seed, and reduced the ensemble's inference time from {{inf_all_us}} to {{inf_ga_us}} µs per flow. It did not improve detection on average: with GA features the hybrid reaches F1 {{hyb_ga_f1_msd}} % and a false-positive rate of {{hyb_ga_far_msd}} %, against {{hyb_all_f1_msd}} % and {{hyb_all_far_msd}} % with all features, and its results vary more between seeds. Only {{ga_common_n}} feature ({{ga_common}}) was selected in all three seeds, and the best fitness values of the three runs were close (Figure 2a), which indicates that many different feature subsets perform almost equally well. The fitness was still rising slowly in the last generation, so a longer search might find slightly better subsets. On this dataset the GA is useful mainly to reduce inference cost.

Table 6 gives recall per family. Botnet, DDoS and brute-force flows are detected almost completely by the hybrid. DoS recall is lower for the signature stage ({{fam_dos_sig}} %) than for the hybrid ({{fam_dos_hyb}} %), and web attacks are the hardest family ({{fam_web_hyb}} % with the hybrid), which is consistent with their small number and their similarity to normal HTTP traffic. Figure 2 shows the GA convergence and the ROC and precision-recall curves of the hybrid, and Figure 3 its confusion matrix.

!table family

!figure fig_ga_roc_pr.png | (a) Best GA fitness per generation for the three seeds. (b) ROC curve (logarithmic false-positive axis) and (c) precision-recall curve of the HBIDS hybrid with all features and with GA-selected features (seed 11).

!figure fig_confusion.png | Confusion matrix of the HBIDS hybrid with all features on the evaluation portion (seed 11). | 300

## 4.3 Collaborative Detection: The Effect of Sharing

Table 7 and Figure 4 report the collaborative experiment. Without sharing, each site detects attacks of the families it was trained on, but its recall on families it has never seen is low ({{c_isolated_foreign_recall}} % on average), because its ensemble was trained on one or two attack families only. Sharing signatures raises the unseen-family recall to {{c_pubsub_foreign_recall}} % with publish-subscribe and to {{c_ledger_foreign_recall}} % (2f + 1 policy) or {{c_strict_foreign_recall}} % (n − f policy) with the ledger, and the mean F1 from {{c_isolated_f1}} % to between {{c_strict_f1}} % and {{c_pubsub_f1}} %. This is the main detection benefit of collaboration, and it comes from the shared signatures, not from the ledger.

!table collab

Without an attack, the ledger gives lower recall than publish-subscribe ({{c_strict_recall}} % with the n − f policy against {{c_pubsub_recall}} %). The reason is visible in Table 8: of the {{honest_pub}} honest signatures published by the six sites, the ledger committed {{honest_comm}} with the 2f + 1 policy and {{strict_honest_comm}} with the n − f policy, because some validators found the remaining signatures to match more than 0.05 % of their own benign traffic. Such a signature also raises false alarms at the receiving sites, so the same check that costs recall keeps the false-positive rate close to that of no sharing: {{c_ledger_far3}} % (2f + 1) and {{c_strict_far3}} % (n − f), against {{c_isolated_far3}} % without sharing and {{c_pubsub_far3}} % with publish-subscribe. Most of the remaining false positives occur at the 21 February site, whose own ensemble produces them in every mode (Figure 4b).

!figure fig_collab.png | Collaborative detection per honest site, mean of three seeds. (a) Recall on attack families absent from the site's own training data. (b) False-positive rate (logarithmic scale). The 14 February site is the poisoning site and is not shown.

## 4.4 Poisoning, Byzantine Validators and Crashes

When the 14 February site publishes {{n_poison}} poisoned signatures built from its most frequent benign keys, publish-subscribe accepts all {{ps_poison_accepted}} of them, because each carries a valid ECDSA signature from a member. The false-positive rate of the honest sites then rises to {{c_pubsub_poisoned_far}} % (Table 7), which would make the IDS unusable. With the ledger and all validators honest, the 2f + 1 policy committed {{led_poison_committed}} of the {{n_poison}} poisoned signatures and the n − f policy committed {{strict_poison_committed}} (Table 8); the false-positive rate of the honest sites was {{c_ledger_poisoned_far3}} % and {{c_strict_poisoned_far3}} %, respectively.

!table admission

The difference between the two policies is explained by the benign traffic of the sites. The poisoned keys are common in the benign traffic of some sites but absent from that of others, so validators whose traffic does not contain a key endorse the signature even though it harms other sites. Under the 2f + 1 policy, a poisoned signature is committed as soon as {{q_val}} of the {{n_val}} validators endorse it. Table 9 and Figure 5 show the consequence: with one malicious validator (the poisoning site's own validator), the 2f + 1 policy committed {{byz_quorum_1}} poisoned signatures. Under the n − f policy, a signature is rejected when more than f = {{f_val}} validators object: {{byz_strict_1}} poisoned signatures were committed with one malicious validator, {{byz_strict_2}} with two to four (the same signatures that the 2f + 1 policy admits without any collusion), and all {{byz_strict_5}} only when five of the six validators were malicious. The strict policy therefore protects every site whose traffic would be harmed, as long as no more than f validators collude with the attacker.

!table byz

!figure fig_byzantine.png | Honest and poisoned signatures committed as the number k of malicious validators grows, for the 2f + 1 and n − f admission policies (n = 6, seed 47). | 400

The price of the strict policy is liveness. With all validators available, both policies committed the same honest signatures as in Table 8. With crashed validators, the 2f + 1 policy committed {{crash_quorum_1}} honest signatures with one crash and {{crash_quorum_2}} with two, whereas the n − f policy committed {{crash_strict_1}} with one crash and {{crash_strict_2}} with two, because every remaining validator must then endorse. Crashed validators also add the endorsement timeout to every block (mean block latency {{crash_quorum_0_lat}} ms without crashes and {{crash_quorum_1_lat}} ms with one crash). A deployment must therefore choose between stronger protection against poisoning (n − f) and tolerance of unavailable validators (2f + 1), or adopt the strict policy with a mechanism for replacing failed validators.

## 4.5 Cost of the Ledger

Table 10 and Figure 6 compare the cost of sharing {{o_T}} signatures through the ledger and through publish-subscribe. Ledger latency grows with the number of validators, from {{o_ledger_4_lat}} ms per 50-signature block with {{o_nmin}} validators to {{o_ledger_13_lat}} ms with {{o_nmax}}, while publish-subscribe needs {{o_pubsub_4_lat}} to {{o_pubsub_13_lat}} ms. Throughput falls from {{o_ledger_4_thr}} to {{o_ledger_13_thr}} signatures per second, against {{o_pubsub_4_thr}} to {{o_pubsub_13_thr}} for publish-subscribe. Communication grows roughly with the square of n, as expected for the all-to-all PBFT phases: {{o_ledger_13_kib}} KiB per signature with {{o_nmax}} validators, against {{o_pubsub_13_kib}} KiB. Each validator stores {{o_ledger_4_store}} KiB per signature with {{o_nmin}} validators and {{o_ledger_13_store}} KiB with {{o_nmax}}, mostly endorsement certificates. CPU time per signature, summed over all validators, rises from {{o_ledger_4_cpu}} ms to {{o_ledger_13_cpu}} ms.

!table overhead

!figure fig_overhead.png | Cost of the permissioned ledger and the authenticated publish-subscribe baseline for 1000 signatures in blocks of 50, mean of three runs (error bars: standard deviation). (a) Commit latency per block. (b) Throughput. (c) Data sent per signature.

These costs are small for the volume of signatures in this study (the six sites published {{honest_pub}} signatures in total), so the ledger is affordable for signature sharing. They would not be affordable for sharing alerts or flow records at line rate, which the design does not attempt.

## 4.6 Detection-Path Cost

Signature lookup took {{sig_us}} µs per flow and the ensemble {{inf_all_us}} µs per flow with all features ({{inf_ga_us}} µs with GA features), measured in batches on two CPU cores; the hybrid therefore processes about {{flows_per_s_all}} flows per second. The ledger is not on the detection path: a site matches flows against its local signature database, and the ledger only adds signatures to that database. The delay between detecting a new attack at one site and protecting the others is the signature-extraction interval plus the commit latency of Section 4.5.

# 5 DISCUSSION

The results answer a basic question about blockchain-based collaborative IDSs: what does the blockchain add? In this study, sharing signatures improved detection substantially, but a simple authenticated publish-subscribe channel delivered that improvement as well as the ledger did. The ledger's contribution is not accuracy. It is admission control, ordering and an auditable record: every committed signature carries the endorsements of the validators that accepted it, the record cannot be changed without detection, and, with the n − f policy, a poisoned signature that would raise false alarms at any honest site with matching traffic was rejected unless more than f validators colluded. Without this check, a single malicious member was able to raise the false-positive rate of all other sites to {{c_pubsub_poisoned_far}} %. These benefits come at a cost that grows with the number of validators (Section 4.5).

The security properties should be stated precisely. The design provides integrity and tamper evidence of the signature record (hash-linked blocks with Merkle roots and signed endorsements), authenticated membership (ECDSA keys fixed in the genesis configuration), agreement on ordering (PBFT), and admission control under the assumptions of Section 3.1. It does not provide confidentiality: signatures are visible to all members. Raw traffic is never shared, but a signature does reveal a port and approximate flow sizes of an attack seen at a site. Where this is sensitive, signatures could be encrypted for the consortium, but key management for such encryption is outside the scope of this paper. Availability depends on the validators: the strict policy loses liveness when more than f validators are unavailable (Section 4.4).

The benign-traffic check also has limits. It protects a site only if that site's own validator, or enough other validators, see the poisoned key in their benign traffic. A site that does not run a validator, or whose traffic is unlike that of the validators, is not protected by others. An attacker who knew the benign traffic of a specific victim could craft a signature that matches only that victim's traffic; such a signature would be rejected by the victim's own validator under the n − f policy only if the victim is among the validators and fewer than f other validators collude. The check is also a threshold rule: a signature that matches up to 0.05 % of a validator's benign flows is accepted, and the threshold trades recall against false alarms.

Several limitations of the study should be noted. The evaluation uses a single benchmark dataset with known labelling and flow-construction problems {@engelen2021,liu2022}, six of its ten days, and sampled subsets because of memory limits; treating capture days as sites is a simulation of a multi-organisation deployment, not a real one. The prototype runs all validators on one machine, so wide-area latency is not included, and the primary is fixed, so a Byzantine or crashed primary is not handled. The GA did not improve accuracy on this dataset. The system has not been deployed on live traffic or validated independently, and no formal security proof is given. Results on Hyperledger Fabric or other production platforms may differ.

# 6 CONCLUSION

This paper studied a hybrid blockchain-based IDS that combines signature matching with a classifier ensemble and shares new signatures through a permissioned ledger, following the architecture of Khonde and Ulagamuthalvi {@khonde2022}. The paper added a benign-traffic endorsement rule with two admission policies, evaluated the system on CSE-CIC-IDS2018 with duplicate removal and a chronological split, separated the effects of the detector, signature sharing and the ledger, and measured the ledger's cost against a non-blockchain baseline. The hybrid detector reached an F1-score of {{hyb_all_f1}} % with a false-positive rate of {{hyb_all_far3}} %. Sharing signatures raised the recall on attack families unseen at a site from {{c_isolated_foreign_recall}} % to above {{c_strict_foreign_recall}} %, but this gain did not depend on the ledger. The ledger's value was in rejecting poisoned signatures: with the n − f policy, {{strict_poison_committed}} of {{n_poison}} poisoned signatures were committed, against all {{ps_poison_accepted}} with publish-subscribe, at a cost of {{o_ledger_4_lat}} to {{o_ledger_13_lat}} ms per block for 4 to 13 validators. Future work should evaluate the design on live, multi-organisation traffic, on a production permissioned platform with view change, and against attackers who target the benign traffic of a specific site.

# DATA AVAILABILITY STATEMENT

The CSE-CIC-IDS2018 dataset is publicly available from the Canadian Institute for Cybersecurity (https://www.unb.ca/cic/datasets/ids-2018.html); the experiments used the CSV mirror at https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv. The code, configuration files, result files and figure scripts that produce every result in this paper are available at [REPOSITORY URL TO BE INSERTED BY THE AUTHORS].

# AUTHOR CONTRIBUTIONS

[TO BE COMPLETED BY THE AUTHORS, for example: SPS: conceptualisation, software, investigation, writing (original draft and revision). HSG: supervision, methodology, writing (review and editing).]

# FUNDING

[TO BE COMPLETED BY THE AUTHORS. If no funding was received: The authors declare that no financial support was received for the research, authorship or publication of this article.]

# CONFLICT OF INTEREST

The authors declare that the research was conducted in the absence of any commercial or financial relationships that could be construed as a potential conflict of interest.

# GENERATIVE AI STATEMENT

[TO BE CONFIRMED BY THE AUTHORS.] Generative AI (Claude, Anthropic) was used to assist in implementing the experimental code and in drafting and editing the revised text. The authors designed the study, checked the code and results, and take full responsibility for the content of the manuscript.

# REFERENCES

!references
