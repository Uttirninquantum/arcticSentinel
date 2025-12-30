import pandas as pd
import numpy as np
import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Dict
import requests


class MITRECrossMapper:
    def __init__(self, input_csv: str = None, threat_df: pd.DataFrame = None):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        if input_csv:
            self.threat_df = pd.read_csv(input_csv)
        elif threat_df is not None:
            self.threat_df = threat_df.copy()
        else:
            raise ValueError("Provide either input_csv or threat_df")
        
        
        self.model = SentenceTransformer('basel/ATTACK-BERT', device=self.device)
        self.cve_descriptions = self.threat_df['description'].fillna('').tolist()
        self.cve_embeddings = self.model.encode(self.cve_descriptions, batch_size=32, show_progress_bar=False)
        
        self.mitre_techniques_df = self._load_mitre_techniques()
        self.mitre_techniques_emb = self.model.encode(
            self.mitre_techniques_df['full_text'].tolist(),
            batch_size=64,
            convert_to_numpy=True
        )
        
        self.mitre_tactics_df = self._load_mitre_tactics()
        self.mitre_tactics_emb = self.model.encode(
            self.mitre_tactics_df['description'].tolist(),
            batch_size=32,
            convert_to_numpy=True
        )
        
    
    def _load_mitre_tactics(self) -> pd.DataFrame:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        data = requests.get(url).json()
        tactics = {}
        for obj in data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                refs = obj.get('external_references', [])
                tactic_id = next((r.get('external_id') for r in refs if r.get('source_name') == 'mitre-attack'), None)
                if tactic_id:
                    tactics[tactic_id] = {
                        'id': tactic_id,
                        'name': obj.get('name'),
                        'description': obj.get('description', '')[:300]
                    }
        return pd.DataFrame(list(tactics.values()))
    
    def _load_mitre_techniques(self) -> pd.DataFrame:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        data = requests.get(url).json()
        techniques = []
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern':
                refs = obj.get('external_references', [])
                mitre_id = next((r.get('external_id') for r in refs if r.get('source_name') == 'mitre-attack'), None)
                if mitre_id:
                    tactic_ids = [phase.get('phase_name') for phase in obj.get('kill_chain_phases', []) 
                                if phase.get('kill_chain_name') == 'mitre-attack']
                    full_text = f"{obj.get('description', '')[:400]} [TACTICS: {', '.join(tactic_ids[:2])}]"
                    techniques.append({
                        'id': mitre_id,
                        'name': obj.get('name')[:60],
                        'description': obj.get('description', '')[:300],
                        'full_text': full_text[:512],
                        'tactic_primary': tactic_ids[0] if tactic_ids else None
                    })
        return pd.DataFrame(techniques)
    
    def get_similar_cves(self, cve_idx: int, top_k: int = 5) -> List[Dict]:
        if len(self.cve_embeddings) <= 1:
            return []
        sims = cosine_similarity([self.cve_embeddings[cve_idx]], self.cve_embeddings)[0]
        sims[cve_idx] = -1
        top_indices = np.argsort(sims)[::-1][:top_k]
        return [{
            'cve_id': self.threat_df.iloc[idx]['cve_id'],
            'description': self.cve_descriptions[idx][:200],
            'similarity': float(sims[idx])
        } for idx in top_indices if idx != cve_idx][:top_k]
    
    def get_similar_mitre(self, cve_desc: str, top_k: int = 5) -> List[Dict]:
        cve_emb = self.model.encode([cve_desc])
        tech_sims = cosine_similarity(cve_emb, self.mitre_techniques_emb)[0]
        top_indices = np.argsort(tech_sims)[::-1][:top_k]
        return [{
            'mitre_id': self.mitre_techniques_df.iloc[idx]['id'],
            'mitre_name': self.mitre_techniques_df.iloc[idx]['name'],
            'mitre_desc': self.mitre_techniques_df.iloc[idx]['description'][:150],
            'similarity': float(tech_sims[idx]),
            'tactic_primary': self.mitre_techniques_df.iloc[idx]['tactic_primary']
        } for idx in top_indices]
    
    def run_mapping(self) -> pd.DataFrame:
        results = []
        for i in range(len(self.threat_df)):
            row = self.threat_df.iloc[i].copy()
            cve_desc = self.cve_descriptions[i]
            
            mitre_matches = self.get_similar_mitre(cve_desc)
            for j in range(5):
                if j < len(mitre_matches):
                    prefix = f"mitre_top{j+1}_"
                    match = mitre_matches[j]
                    row[f"{prefix}id"] = match['mitre_id']
                    row[f"{prefix}name"] = match['mitre_name']
                    row[f"{prefix}desc"] = match['mitre_desc']
                    row[f"{prefix}sim"] = match['similarity']
                else:
                    prefix = f"mitre_top{j+1}_"
                    row[f"{prefix}id"] = row[f"{prefix}name"] = row[f"{prefix}desc"] = row[f"{prefix}sim"] = None
            
            cve_matches = self.get_similar_cves(i)
            for j in range(5):
                if j < len(cve_matches):
                    prefix = f"cve_sim{j+1}_"
                    match = cve_matches[j]
                    row[f"{prefix}id"] = match['cve_id']
                    row[f"{prefix}desc"] = match['description']
                    row[f"{prefix}sim"] = match['similarity']
                else:
                    prefix = f"cve_sim{j+1}_"
                    row[f"{prefix}id"] = row[f"{prefix}desc"] = row[f"{prefix}sim"] = None
            
            if mitre_matches:
                tactic_id = mitre_matches[0]['tactic_primary']
                tactic_row = self.mitre_tactics_df[self.mitre_tactics_df['id'] == tactic_id]
                if not tactic_row.empty:
                    t_row = tactic_row.iloc[0]
                    row['primary_tactic_id'] = tactic_id
                    row['primary_tactic_name'] = t_row['name']
                    row['primary_tactic_desc'] = t_row['description']
            
            results.append(row)
        return pd.DataFrame(results)