"""PR10 independent world-document audit. No QA-only files read. Frozen protocol."""
import copy, hashlib, json, math, os, random, shutil
from collections import Counter, defaultdict
from pathlib import Path
import torch
import torch.nn.functional as F
from backend.concept_system import ConceptSession, ConceptSystem, WORD, batch_text
from backend.structural_growth import Proposal

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "concept-discovery-v2" / "data_progressive"
OUT = ROOT / "world_audit"
OUT.mkdir(exist_ok=True)
torch.set_num_threads(1)
SEEDS = (7,17)
LIMIT = 76

def read_jsonl(rel):
    # Hard deny QA files; training and evaluation must not inspect them.
    assert "qa_only" not in str(rel).lower()
    p = DATA / rel
    return [json.loads(x) for x in p.read_text(encoding="utf8").splitlines() if x.strip()]

pilot=read_jsonl("sources/original_pilot.jsonl")
longform=read_jsonl("sources/original_longform.jsonl")
nahalia=read_jsonl("worlds/world_01/documents.jsonl")
all_docs=pilot+longform+nahalia
counts=Counter(d.get("family_id") for d in all_docs)
lengths={d["document_id"]:len(WORD.findall(d["text"])) for d in all_docs}
splits=Counter(d.get("split") for d in all_docs)
# Frozen before any predictions: Nahlia and archive-trails are out-of-family targets;
# in a separate temporal probe, only Nahlia days 1-8 may be shown.
train_pilot=[d for d in pilot if d.get("split")=="train" and d.get("family_id") not in ("archive-trails","nahalia-chronicle-01")]
train_long=[d for d in longform if d.get("split")=="train" and d.get("family_id")!="archive-trails"]
train=train_pilot+train_long
heldout=[d for d in longform if d.get("family_id")=="archive-trails"]
world=sorted(nahalia,key=lambda x:x.get("document_day",0))
assert len(world)==12 and train and heldout
assert not any(d.get("family_id") in {x.get("family_id") for x in heldout+world} for d in train)
assert not any(d.get("split")=="final" for d in train)
def chunks(text,limit=LIMIT):
    tokens=WORD.findall(text)
    return [" ".join(tokens[i:i+limit]) for i in range(0,len(tokens),limit)]
def rows_from_docs(docs,cap=30):
    rows=[]
    for d in docs:
        xs=chunks(d["text"])
        for i in range(0,len(xs)-2,3):
            rows.append({"documents":xs[i:i+3],"question":"איזה פרט נשמר?","options":["הראשון","השני"],"target":0,
                         "origin":d["document_id"],"family":d.get("family_id")})
    return rows[:cap]
training_rows=rows_from_docs(train)
world_early=rows_from_docs(world[:8])
assert len(training_rows)>=4 and len(world_early)>=2
# No QA data nor leaked future days may be used to decide writes.
eval_docs=heldout+world
def single_features(model,texts):
    with torch.no_grad():
        docs=batch_text([[x] for x in texts],model.config.vocab)
        return model.document_features(docs)[:,0]
def summary_metrics(model,texts):
    with torch.no_grad():
        features=single_features(model,texts)
        output=model.growth.retrieval(model.bootstrap,features)
        return output.detach()
def against(model,phrases,source_docs):
    # Phrase-linked windows selected from natural document strings; no generated answer labels.
    ret={}
    for word in phrases:
        found=[]
        for d in source_docs:
            tokens=WORD.findall(d["text"])
            parts=WORD.findall(word)
            for i in range(len(tokens)-len(parts)+1):
                if tokens[i:i+len(parts)]==parts:
                    found.append((d["document_id"]," ".join(tokens[max(0,i-18):min(len(tokens),i+len(parts)+50)])))
                    break
        ret[word]=found
    return ret
phrases=("נועם רביב","נועם כהן","פינת מתכת","ידית עץ","מד הנחושת")
phrase_docs=against(None,phrases,world)
# Freeze the actual evaluation text before model/seed evaluation.
probe=[]
for d in heldout+world[8:]:
    probe.extend(chunks(d["text"])[:2])
probe=probe[:32]
assert probe
frozen_probes_hash=hashlib.sha256(json.dumps(probe,ensure_ascii=False).encode()).hexdigest()
def cosine(a,b):
    return float(F.cosine_similarity(a.reshape(1,-1),b.reshape(1,-1),dim=-1).item())
def phrase_probes(model):
    unique=[]; labels=[]
    for name,entries in phrase_docs.items():
        for doc_id,win in entries[:4]:
            unique.append(win);labels.append((name,doc_id))
    if not unique: return {}
    v=summary_metrics(model,unique)
    records={}
    for j,(name,doc_id) in enumerate(labels):
        records.setdefault(name,[]).append({"document":doc_id,"vec":v[j]})
    result={}
    for a,b in [("נועם רביב","נועם כהן"),("פינת מתכת","ידית עץ")]:
        if a in records and len(records[a])>=2 and b in records:
            val=cosine(records[a][0]["vec"],records[a][1]["vec"])-cosine(records[a][0]["vec"],records[b][0]["vec"])
            result[a+"_same_vs_other_margin"]=round(val,6)
    return result
def forward_delta(model, doc):
    text=chunks(doc["text"])[0]
    row={"documents":[text],"question":"היכן נרשם האירוע?",
         "options":["במחסן","בארכיון"],"target":0}
    from backend.concept_system import batch_text
    xs=(batch_text([row["documents"]],model.config.vocab),
        batch_text([[row["question"]]],model.config.vocab)[:,0],
        batch_text([row["options"]],model.config.vocab))
    with torch.no_grad():
        full=model(*xs)[0]
        muted=model(*xs,mute_bootstrap=True)[0]
    return round(float((full-muted).abs().max()),8)
def ablate_new(model, fn, only_slots=None):
    growth,bank=model.growth,model.bootstrap
    slots=(growth.protected & ~growth.original_slots).nonzero().flatten().tolist() if only_slots is None else only_slots
    before=fn()
    backups=[]
    with torch.no_grad():
        for i in slots:
            backups.append((i,bank.enter.weight[i].clone(),bank.compose.weight[:,i].clone()))
            bank.enter.weight[i].zero_();bank.compose.weight[:,i].zero_()
        after=fn()
        for i,w,r in backups:
            bank.enter.weight[i].copy_(w);bank.compose.weight[:,i].copy_(r)
        restored=fn()
    return before,after,restored,len(slots)
def sha_params(model):
    return hashlib.sha256(b"".join(x.detach().cpu().numpy().tobytes() for x in model.bootstrap.parameters())).hexdigest()
def audit_seed(seed):
    torch.manual_seed(seed);random.seed(seed)
    ckpt=ROOT/"pilot"/f"seed-{seed}.pt"
    session_path=OUT/f"seed-{seed}-world.pt"
    if ckpt.exists(): shutil.copyfile(ckpt,session_path)
    sess=ConceptSession(session_path)
    model=sess.model
    g=model.growth
    input_ckpt=ckpt.exists()
    baseline=copy.deepcopy(model.state_dict())
    full_pre_protected=g.protected.detach().clone()
    occupied_pre=int(g.occupied.sum());accepted_pre=int(g.accepted)
    base_phrase=phrase_probes(model)
    before_retrieval=summary_metrics(model,probe)
    before_forward0=forward_delta(model,world[8])
    # The studied condition: learn on existing documents only (no QA).
    # Make three short chronological passes; policy is not instructed which slot to use.
    stats=[]
    for e in range(3):
        selection=training_rows[e*4:e*4+8]
        if len(selection)<2: selection=training_rows[:8]
        stats.append(sess.train_structural(selection,limit=12,write_cost=.0001))
    # Separate within-world temporal diagnostic, clearly NOT domain heldout.
    temporal_before=int(g.accepted)
    for e in range(2):
        stats.append(sess.train_structural(world_early[e*4:e*4+8],limit=12,write_cost=.0001))
    learned=summary_metrics(model,probe)
    after_phrase=phrase_probes(model)
    slots=(g.protected & ~g.original_slots).nonzero().flatten().tolist()
    created_after=int(g.accepted)-accepted_pre
    incremental_slots=(g.protected & ~full_pre_protected).nonzero().flatten().tolist()
    delta=float((learned-before_retrieval).abs().mean())
    probe_fn=lambda:summary_metrics(model,probe)
    old,muted,restored,nslots=ablate_new(model,probe_fn,incremental_slots)
    # Surgical intervention of ONLY newly accepted PR4 writes, never pilot writes.
    causal=float((old-muted).abs().mean())
    exact=bool(torch.equal(old,restored))
    before_forward=forward_delta(model,world[8])
    with torch.no_grad(): original_gain=model.bootstrap_gain.clone();model.bootstrap_gain.fill_(.3)
    gain_forward=forward_delta(model,world[8])
    with torch.no_grad():model.bootstrap_gain.copy_(original_gain)
    # Replay frozen-state comparison: no extra accepted PR4 writes, matched exposure is fixed.
    no_write=ConceptSession(OUT/f"seed-{seed}-no-write.pt").model
    no_write.load_state_dict(baseline)
    nowrite_phrases=phrase_probes(no_write)
    no_write_ret=summary_metrics(no_write,probe)
    # Matched-write-content control: same number of new neurons, identical weight
    # norms and inputs, but reassign output content across newly created slots.
    scrambled=copy.deepcopy(model)
    scramble_difference=None
    if len(incremental_slots)>1:
        with torch.no_grad():
            k=incremental_slots
            shuffled=k[1:]+k[:1]
            for target,source in zip(k,shuffled):
                scrambled.bootstrap.compose.weight[:,target]=model.bootstrap.compose.weight[:,source].clone()
        scrambled_result=summary_metrics(scrambled,probe)
        scramble_difference=round(float((scrambled_result-old).abs().mean()),8)
    drift=float((old-no_write_ret).abs().mean())
    protected=g.protected.detach().clone();anchors=g.anchor_enter.detach().clone()
    sess.save()
    restored_session=ConceptSession(session_path)
    state_equal=all(torch.equal(v,restored_session.model.state_dict()[k]) for k,v in model.state_dict().items())
    # One limited continued training pass, no Final. 
    cont=sess.train_structural(training_rows[:8],enable=False,limit=8,write_cost=.0001)
    retained=bool(torch.equal(anchors[protected],g.anchor_enter[protected]))
    # Token collision diagnostics on dataset text, not a learned semantic test.
    return {
     "seed":seed,"used_pilot_checkpoint":input_ckpt,"initial_step":int(sess.step),
     "train_family_count":len({d.get("family_id") for d in train}),
     "train_docs":len(train),"within_world_train_days":8,"evaluation_world_days":[9,10,11,12],
     "heldout_domains":[d.get("family_id") for d in heldout],
     "growth_stats":stats,"continued_stats":cont,
     "occupied_before":occupied_pre,"occupied_after":int(g.occupied.sum()),
     "accepted_before":accepted_pre,"new_accepted":created_after,
     "world_temporal_accepted":int(g.accepted)-temporal_before,
     "new_slots_sample":incremental_slots,"probe_count":len(probe),
     "matched_content_permutation_abs_delta":scramble_difference,
     "probe_retrieval_delta_vs_no_write":round(drift,8),
     "probe_retrieval_delta_vs_initial":round(delta,8),
     "incremental_pr4_ablation_mean_abs":round(causal,8),"incremental_pr4_ablation_restore_exact":exact,
     "checkpoint_exact":state_equal,"protected_anchors_unchanged_after_continuation":retained,
     "full_forward_bootstrap_delta_at_stored_gain_before":before_forward0,
     "full_forward_bootstrap_delta_at_stored_gain_after":before_forward,
     "full_forward_bootstrap_delta_at_gain_point3":gain_forward,
     "initial_phrase_margins":base_phrase,"trained_phrase_margins":after_phrase,
     "no_write_phrase_margins":nowrite_phrases,
    }
def hash_collision_metrics(docs,vocab=2048):
    words={w for d in docs for w in WORD.findall(d["text"])}
    from backend.concept_system import encode
    hashes=defaultdict(list)
    for w in words:hashes[encode(w,vocab)[0]].append(w)
    collisions={k:v for k,v in hashes.items() if len(v)>1}
    return {"distinct_tokens":len(words),"hash_bins_used":len(hashes),"collided_bins":len(collisions),
            "collided_unique_tokens":sum(len(v) for v in collisions.values()),
            "sample_collisions":list(collisions.values())[:6]}
report={
 "source_model_sha":"207cb5a34b5c469e90a2ef131a530b2c44f3349d",
 "data_sha":"f991e4f201364294af866b0add51793e9a7a57bc",
 "scope":"PR4 real original documents only; QA-only and Final never read; training on pilot and days1-8; archive + days9-12 probes",
 "data":{"documents":len(all_docs),"families":len(counts),"family_counts":dict(counts),"splits":dict(splits),
 "tokens_min":min(lengths.values()),"tokens_max":max(lengths.values()),
 "over_96_count":sum(v>96 for v in lengths.values()),
 "tokens_total":sum(lengths.values()),"eval_probe_sha256":frozen_probes_hash,
 "eval_probe_count":len(probe),"training_rows":len(training_rows),"world_early_rows":len(world_early)},
 "hash_collisions":hash_collision_metrics(all_docs),
 "phrase_doc_counts":{k:len(v) for k,v in phrase_docs.items()},
 "runs":[audit_seed(s) for s in SEEDS]
}
(OUT/"audit_metrics.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf8")
print("AUDIT_JSON_START")
print(json.dumps(report,ensure_ascii=False,indent=2))
print("AUDIT_JSON_END")
