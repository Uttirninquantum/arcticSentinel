import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import re
from datetime import datetime
import pandas as pd
import numpy as np
import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Dict
import requests


class MITRECrossMapper:
    def __init__(self, input_csv: str):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        self.threat_df = pd.read_csv(input_csv)

        self.model = SentenceTransformer("basel/ATTACK-BERT", device=self.device)
        self.cve_descriptions = self.threat_df["description"].fillna("").tolist()
        self.cve_embeddings = self.model.encode(
            self.cve_descriptions, batch_size=32, show_progress_bar=True
        )

        self.mitre_techniques_df = self._load_mitre_techniques()
        self.mitre_techniques_emb = self.model.encode(
            self.mitre_techniques_df["full_text"].tolist(),
            batch_size=64,
            convert_to_numpy=True,
        )
        self.mitre_tactics_df = self._load_mitre_tactics()

    def _load_mitre_tactics(self) -> pd.DataFrame:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        data = requests.get(url).json()
        tactics = {}
        for obj in data["objects"]:
            if obj.get("type") == "x-mitre-tactic":
                refs = obj.get("external_references", [])
                tactic_id = next(
                    (
                        r.get("external_id")
                        for r in refs
                        if r.get("source_name") == "mitre-attack"
                    ),
                    None,
                )
                if tactic_id:
                    tactics[tactic_id] = {
                        "id": tactic_id,
                        "name": obj.get("name"),
                        "description": obj.get("description", "")[:300],
                    }
        return pd.DataFrame(list(tactics.values()))

    def _load_mitre_techniques(self) -> pd.DataFrame:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        data = requests.get(url).json()
        techniques = []
        for obj in data["objects"]:
            if obj.get("type") == "attack-pattern":
                refs = obj.get("external_references", [])
                mitre_id = next(
                    (
                        r.get("external_id")
                        for r in refs
                        if r.get("source_name") == "mitre-attack"
                    ),
                    None,
                )
                if mitre_id:
                    tactic_ids = [
                        phase.get("phase_name")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ]
                    full_text = f"{obj.get('description', '')[:400]} [TACTICS: {', '.join(tactic_ids[:2])}]"
                    techniques.append(
                        {
                            "id": mitre_id,
                            "name": obj.get("name")[:60],
                            "description": obj.get("description", "")[:300],
                            "full_text": full_text[:512],
                            "tactic_primary": tactic_ids[0] if tactic_ids else None,
                        }
                    )
        return pd.DataFrame(techniques)

    def get_similar_cves(self, cve_idx: int, top_k: int = 5) -> List[Dict]:
        if len(self.cve_embeddings) <= 1:
            return []

        sims = cosine_similarity([self.cve_embeddings[cve_idx]], self.cve_embeddings)[0]
        sims[cve_idx] = -1

        top_indices = np.argsort(sims)[::-1][:top_k]
        similar_cves = []

        for idx in top_indices:
            if idx != cve_idx:
                similar_cves.append(
                    {
                        "cve_id": self.threat_df.iloc[idx]["cve_id"],
                        "description": self.cve_descriptions[idx][:200],
                        "similarity": float(sims[idx]),
                    }
                )

        return similar_cves[:top_k]

    def get_similar_mitre(self, cve_desc: str, top_k: int = 5) -> List[Dict]:
        cve_emb = self.model.encode([cve_desc])
        tech_sims = cosine_similarity(cve_emb, self.mitre_techniques_emb)[0]

        top_indices = np.argsort(tech_sims)[::-1][:top_k]
        similar_mitre = []

        for idx in top_indices:
            mitre_row = self.mitre_techniques_df.iloc[idx]
            similar_mitre.append(
                {
                    "mitre_id": mitre_row["id"],
                    "mitre_name": mitre_row["name"],
                    "mitre_desc": mitre_row["description"][:150],
                    "similarity": float(tech_sims[idx]),
                    "tactic_primary": mitre_row["tactic_primary"],
                }
            )

        return similar_mitre[:top_k]

    def batch_map_all(self) -> pd.DataFrame:
        results = []

        for i in range(len(self.threat_df)):

            row = self.threat_df.iloc[i].copy()
            cve_desc = self.cve_descriptions[i]

            mitre_matches = self.get_similar_mitre(cve_desc)
            for j in range(5):
                prefix = f"mitre_top{j+1}_"
                m = mitre_matches[j]
                row[f"{prefix}id"] = m["mitre_id"]
                row[f"{prefix}name"] = m["mitre_name"]
                row[f"{prefix}desc"] = m["mitre_desc"]
                row[f"{prefix}sim"] = m["similarity"]

            cve_matches = self.get_similar_cves(i)
            for j in range(5):
                prefix = f"cve_sim{j+1}_"
                c = cve_matches[j]
                row[f"{prefix}id"] = c["cve_id"]
                row[f"{prefix}desc"] = c["description"]
                row[f"{prefix}sim"] = c["similarity"]

            if mitre_matches:
                tactic_id = mitre_matches[0]["tactic_primary"]
                tactic_row = self.mitre_tactics_df[
                    self.mitre_tactics_df["id"] == tactic_id
                ]
                if not tactic_row.empty:
                    t_row = tactic_row.iloc[0]
                    row["primary_tactic_id"] = tactic_id
                    row["primary_tactic_name"] = t_row["name"]
                    row["primary_tactic_desc"] = t_row["description"]

            results.append(row)

        return pd.DataFrame(results)

    def run_mapping(self, output_csv: str):
        start = time.time()
        enriched_df = self.batch_map_all()

        output_cols = [
            "cve_id",
            "vendor",
            "product",
            "description",
            "mitre_top1_id",
            "mitre_top1_name",
            "mitre_top1_desc",
            "mitre_top1_sim",
            "mitre_top2_id",
            "mitre_top2_name",
            "mitre_top2_desc",
            "mitre_top2_sim",
            "mitre_top3_id",
            "mitre_top3_name",
            "mitre_top3_desc",
            "mitre_top3_sim",
            "mitre_top4_id",
            "mitre_top4_name",
            "mitre_top4_desc",
            "mitre_top4_sim",
            "mitre_top5_id",
            "mitre_top5_name",
            "mitre_top5_desc",
            "mitre_top5_sim",
            "cve_sim1_id",
            "cve_sim1_desc",
            "cve_sim1_sim",
            "cve_sim2_id",
            "cve_sim2_desc",
            "cve_sim2_sim",
            "cve_sim3_id",
            "cve_sim3_desc",
            "cve_sim3_sim",
            "cve_sim4_id",
            "cve_sim4_desc",
            "cve_sim4_sim",
            "cve_sim5_id",
            "cve_sim5_desc",
            "cve_sim5_sim",
            "primary_tactic_id",
            "primary_tactic_name",
        ]

        enriched_df = enriched_df[
            [col for col in output_cols if col in enriched_df.columns]
        ]
        enriched_df.to_csv(output_csv, index=False)

        elapsed = time.time() - start

        first_row = enriched_df.iloc[0]
        mitre_cols = sum(
            1 for i in range(1, 6) if pd.notna(first_row.get(f"mitre_top{i}_id", None))
        )
        cve_cols = sum(
            1 for i in range(1, 6) if pd.notna(first_row.get(f"cve_sim{i}_id", None))
        )

