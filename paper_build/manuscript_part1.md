!title Poisoning-Resistant Signature Sharing for Hybrid Intrusion Detection Using a Permissioned Blockchain Ledger

!authors

# ABSTRACT

Collaborative intrusion detection systems share attack signatures so that an attack detected at one site can be blocked at others. Blockchain has been proposed as the sharing medium, but earlier evaluations have not separated the contribution of the ledger from that of the detector, and they have not examined whether shared signatures can be used to attack the receivers. This paper revises and extends a hybrid blockchain-based intrusion detection system (HBIDS) that combines signature matching with a classifier ensemble and exchanges new signatures through a permissioned ledger. The architecture follows earlier work by Khonde and Ulagamuthalvi; the contributions of this paper are an endorsement rule that rejects poisoned signatures and a leakage-controlled evaluation. Each validator endorses a signature only if it matches at most 0.05 % of that validator's own benign traffic, and a signature is committed only with a threshold of signed endorsements, followed by Practical Byzantine Fault Tolerance (PBFT) agreement on the block. HBIDS was evaluated on six capture days of CSE-CIC-IDS2018 using a chronological split per class, after removing {{dup_total_fmt}} exact duplicate flows ({{dup_pct}} % of the records). The hybrid detector reached an F1-score of {{hyb_all_f1}} % and a false-positive rate of {{hyb_all_far}} % (mean of three seeds). {{abstract_collab}} {{abstract_poison}} {{abstract_overhead}} The results show that the ledger does not improve detection accuracy by itself; its benefit lies in admission control, ordering and tamper evidence for shared signatures, at a measurable cost.

!keywords Keywords: blockchain, collaborative intrusion detection, signature sharing, data poisoning, Byzantine fault tolerance, CSE-CIC-IDS2018

# 1 INTRODUCTION

Intrusion detection systems (IDSs) monitor hosts or networks and raise alerts when traffic matches known attack patterns or departs from expected behaviour {@khraisat2019,ayyagari2021}. Signature-based detection is precise for known attacks but cannot recognise attacks for which no signature exists, whereas anomaly-based and learning-based detection can generalise to new traffic at the cost of more false alarms {@khraisat2019}. Hybrid designs therefore pass traffic through a signature stage first and through a learned detector second.

When several organisations operate IDSs, a signature created at one site can protect the others if it is shared quickly. Collaborative intrusion detection systems (CIDSs) exchange alerts or signatures for this purpose, and blockchain has been proposed as the exchange medium because it removes the single trusted coordinator and keeps an append-only, tamper-evident record {@meng2018,alexopoulos2017,alkadi2020,alemari2022}. A blockchain, however, guarantees that the members agree on what was recorded; it does not by itself guarantee that what was recorded is correct. A compromised member can publish a "signature" that matches common benign traffic, and every receiver that installs it will then block or flag its own legitimate traffic. This is a form of data poisoning {@biggio2018}, and in a CIDS it is the threat that blockchain-based sharing must be shown to resist.

Khonde and Ulagamuthalvi {@khonde2022} proposed a hybrid IDS in which a signature phase is followed by a genetic-algorithm-assisted classifier ensemble, and new signatures are exchanged between nodes through a Hyperledger-based blockchain with initiator and validator nodes. The architecture evaluated in this paper follows that design, and the present manuscript does not claim the two-phase architecture as new. Every result reported here was produced by new experiments, and the code that produces them is publicly released.

Three gaps motivate this work. First, earlier evaluations of blockchain-based IDSs report detection accuracy for the whole system, so it is not possible to tell whether improvements come from the detector, from the shared signatures, or from the ledger itself. Second, validation of shared signatures is usually limited to checking that the sender is authorised; whether a signature is harmful to the receivers is not tested. Third, many evaluations on flow datasets split records at random, although such datasets contain many duplicate and temporally correlated flows, which inflates reported accuracy {@engelen2021,liu2022,arp2022}.

The contributions of this paper are as follows.

- An endorsement rule for signature sharing in which each validator tests every incoming signature against its own benign traffic, and a signature is committed only with a threshold of signed endorsements, followed by PBFT agreement {@castro1999} on the block. Two thresholds are compared: a Byzantine quorum (2f + 1) and a strict rule that rejects a signature when more than f validators object (n − f). Raw traffic never leaves a site; validators exchange only signatures and signed endorsements.
- A leakage-controlled evaluation on six days of CSE-CIC-IDS2018 {@sharafaldin2018}: duplicate removal, a chronological split within every (day, label) group, removal of evaluation flows identical to training flows, and complete metrics with confusion counts and per-family recall.
- An ablation that separates the signature stage, each classifier, the ensemble, genetic-algorithm feature selection, signature sharing, and the ledger, including a collaborative experiment in which each capture day is treated as a separate site.
- Measurements of the ledger's cost (latency, throughput, communication, CPU time and storage) against an authenticated publish-subscribe channel that shares the same signatures without a ledger, and of its behaviour under poisoning, Byzantine validators and crashed validators.

The security properties claimed are limited to those that the design provides and the experiments test: integrity and tamper evidence of the shared signature record, authenticated membership, agreement on ordering, and admission control against poisoned signatures, whose strength depends on the admission threshold and on how many validators are malicious (Section 4.4). Blockchain does not provide confidentiality, and availability depends on the health and connectivity of the validator nodes {@guo2022,feng2019}; these limits are discussed in Section 5.

The remainder of the paper is organised as follows. Section 2 reviews related work. Section 3 describes the system, the threat model, the dataset and the evaluation protocol. Section 4 presents the results. Section 5 discusses the role of the ledger and the limitations of the study, and Section 6 concludes.

# 2 RELATED WORK

Meng et al. {@meng2018} reviewed how blockchain can support intrusion detection, in particular collaborative detection, and concluded that blockchain addresses data sharing and trust among nodes but does not solve all IDS problems. Alexopoulos et al. {@alexopoulos2017} proposed recording the alerts of CIDS monitors as blockchain transactions so that the exchanged information is tamper-resistant and accountable. Alkadi et al. {@alkadi2020} and Al-E'mari et al. {@alemari2022} reviewed blockchain-based IDSs for cloud and general settings and identified trust management, privacy and performance as open issues. Mathew et al. {@mathew2022} surveyed the combination of CIDSs and blockchain for industrial Internet of Things (IoT) networks.

Several systems couple blockchain with collaborative detection. Li et al. {@li2021} built a blockchain-based framework for challenge-based collaborative intrusion detection networks, in which trust among nodes is computed from challenge responses and recorded on chain, and later extended collaborative detection with blockchain to software-defined-network-assisted cyber-physical systems {@li2023}. Babu et al. {@babu2022} combined physically unclonable function (PUF) based device authentication with a blockchain-based IDS for IoT urban data and DDoS attacks. Learning-based designs include the deep-learning IDS with blockchain of Saveetha and Maragatham {@saveetha2022}, the optimisation-based deep-learning model for blockchain-enabled cyber-physical systems of Mansour {@mansour2022}, and the lightweight blockchain security model for industrial IoT of Selvarajan et al. {@selvarajan2023}; Shafay et al. {@shafay2023} reviewed the broader integration of blockchain and deep learning. Wider surveys cover blockchain for the IoT {@dai2019,khan2018} and blockchain security {@guo2022}.

The work closest to this paper is that of Khonde and Ulagamuthalvi {@khonde2022}, who proposed the hybrid architecture described in Section 1 and reported that signature exchange through Hyperledger improved detection. The present paper uses the same architectural pattern but differs in three respects: shared signatures are tested against each validator's benign traffic before they can be committed; the effect of sharing and the effect of the ledger are measured separately, together with a non-blockchain baseline; and the evaluation removes duplicates and uses a chronological split.

Data quality in CSE-CIC-IDS2018 has been examined by Engelen et al. {@engelen2021} and Liu et al. {@liu2022}, who reported labelling and flow-construction errors, and Arp et al. {@arp2022} described pitfalls such as data snooping and sampling bias in machine learning for security. These studies motivate the evaluation protocol in Section 3.7. Table 1 summarises the related systems.

!table related

# 3 MATERIALS AND METHODS

## 3.1 System Model and Threat Model

The system consists of N IDS sites operated by different organisations that agree to share signatures. Each site runs the detector in Figure 1 on its own traffic and also acts as a validator of the shared ledger, so the number of validators is n = N. Membership is permissioned: the public key of every site is fixed in the genesis configuration, and every message is signed with the Elliptic Curve Digital Signature Algorithm (ECDSA) on the NIST P-256 curve with SHA-256 {@johnson2001}. A ledger of n validators tolerates f = ⌊(n − 1)/3⌋ Byzantine validators {@castro1999}.

The adversary may control (i) one or more initiator sites that publish forged or poisoned signatures, (ii) up to k validators that endorse every transaction regardless of its content, and (iii) validators that crash and stop responding. Poisoned signatures are constructed from the most frequent benign flow keys observed at the malicious site, which is a natural poisoning strategy for an attacker who knows only its own traffic. Out of scope are a Byzantine primary (the prototype does not implement view change), evasion attacks that modify attack traffic to avoid detection, denial-of-service attacks on the network links, and confidentiality of signatures among members. Raw traffic and flow records are never shared; validators exchange only signatures, which describe attack traffic, and signed endorsements.

!figure fig_architecture.png | Architecture of HBIDS. Upper panel: detection at one site (Phase 1 signature matching, Phase 2 classifier ensemble, signature extraction). Lower panel: the permissioned signature ledger (endorse, order, commit). Only signatures and signed endorsements leave a site.

## 3.2 Phase 1: Signature Format and Matching

A flow is described by a discrete key

!eq key(x) = (protocol, destination port, b(x₁), b(x₂), b(x₃), b(x₄), b(x₅)),  b(v) = min(⌊log₂(1 + v)⌋, 24),   (1)

where x₁ to x₅ are the total forward packets, total backward packets, total forward bytes, total backward bytes and initial forward TCP window size of the flow. The bins are fixed in advance and do not depend on any data, so every site computes identical keys without exchanging traffic, and no information from the evaluation data can enter the definition of a signature. A signature is a key together with its metadata (Table 2). A flow matches a signature when its key equals the signature key; matching is a hash-set lookup. Flows that match a signature in the local database are raised as alerts; the others pass to Phase 2.

A site creates signatures from attack flows in two ways: from labelled attack flows in its training data, and from flows that the Phase 2 detector flags during operation (the signature window, Section 3.7). A key becomes a signature only if at least 20 flagged flows share it (minimum support). Before publishing, the site checks the signature against its own benign traffic with the same rule that validators apply (Equation 2).

!table sigformat

## 3.3 Phase 2: Feature Selection and Classifier Ensemble

Phase 2 classifies the flows that do not match a signature. The candidate features are the {{n_feat}} non-constant numerical features produced by CICFlowMeter, after removing identifiers (flow identifier, source and destination IP addresses, source port and timestamp) to avoid shortcut learning {@arp2022}. The destination port is used only in signature keys.

Feature selection uses a genetic algorithm (GA) {@goldberg1989}. A chromosome is a binary mask over the candidate features. The fitness of a mask is the macro-averaged F1-score of a Random Forest trained on the earlier 75 % and scored on the later 25 % of every (day, label) group of the training portion (a chronological validation split inside the training data, mirroring the main split), minus 0.002 per selected feature. The GA settings are listed in Table 3.

The ensemble contains a multilayer perceptron (MLP), XGBoost {@chen2016} and a Random Forest {@breiman2001}, implemented with scikit-learn {@pedregosa2011} and the XGBoost library. Each member outputs an attack probability; the ensemble prediction is the majority vote of the three thresholded members, and the mean probability is used as the score for ROC and precision-recall curves. Hyperparameters were fixed before evaluation and are given in Table 3. The ensemble was trained twice, once on all {{n_feat}} features and once on the GA-selected features, so that the effect of feature selection can be measured.

!table hyper

## 3.4 Signature Ledger: Endorse, Order, Commit

Signatures are shared as ledger transactions. A transaction contains the signature payload, the identity of the initiating site and the initiator's ECDSA signature over the payload. Blocks contain up to 50 transactions. The protocol runs in six steps (Figure 1).

- SUBMIT. The initiator sends a batch of signed transactions to the primary validator.
- ENDORSE request. The primary forwards the candidate transactions to all n validators.
- ENDORSE. Each validator j returns a signed bitmap that endorses transaction t if and only if the initiator's signature is valid, the initiator is a member, the support is at least 20, and the signature matches no more than a fraction τ = 0.0005 of the validator's own benign reference flows:

!eq endorse_j(s) = 1  if  |{x ∈ B_j : key(x) = key(s)}| / |B_j| ≤ τ,  and 0 otherwise,   (2)

where B_j is the benign traffic in validator j's training period. The validator stores B_j only as key counts.
- PRE-PREPARE. The primary keeps every transaction that has at least m positive endorsements, attaches the signed endorsements as a certificate, and proposes the block to all validators. Two admission policies were evaluated: the quorum policy, m = 2f + 1, under which a signature needs a Byzantine quorum of approvals; and the strict policy, m = n − f, under which a signature is rejected as soon as more than f validators object. The strict policy protects every site whose benign traffic would be harmed, at the cost of liveness when more than f validators are unavailable. The block header contains the height, the hash of the previous block, a timestamp, the Merkle root {@merkle1988} of the transactions, the number of transactions and the sequence number (Table 2).
- PREPARE and COMMIT. Each validator verifies the Merkle root and re-verifies every endorsement certificate before sending PREPARE, so that a faulty primary cannot include a transaction with fewer than m valid endorsements. After 2f + 1 matching PREPARE messages a validator sends COMMIT, and after 2f + 1 COMMIT messages it appends the block to its local ledger file, following the PBFT three-phase pattern {@castro1999}.
- REPLY. Each validator informs the initiator, and every site adds the committed signatures to its local signature database.

The prototype is written in Python with asyncio; each validator runs as a separate operating-system process and communicates over TCP. The primary is fixed (view change is not implemented). A production deployment would more likely use a permissioned platform such as Hyperledger Fabric {@androulaki2018}, whose execute-order-validate design separates endorsement from ordering in a similar way. The repository includes a Fabric chaincode that expresses the same endorsement rule through an endorsement policy and private data collections, but it was not executed for this paper, and all ledger results come from the Python prototype.

## 3.5 Non-Blockchain Baseline

To separate the effect of the ledger from the effect of sharing, the same signatures were also distributed through an authenticated publish-subscribe channel. The initiator signs each transaction with ECDSA and sends it directly to every subscriber; a subscriber verifies the signature and membership and installs the signature. There is no endorsement quorum, no benign-traffic check, no ordering agreement and no ledger. This baseline represents a conventional, authenticated, distributed signature-sharing mechanism.
