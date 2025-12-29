# models/threat_timeline.py
# COMPLETE ThreatTimelinePipeline (EARLIER VERSION - FULLY FUNCTIONAL)

import pandas as pd
import requests
import numpy as np
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Dict
import re
from datetime import datetime

class ThreatTimelinePipeline:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"⚡ THREAT TIMELINE Pipeline ({self.device})")
        
        # Preload MITRE with detailed tactics
        self.model = SentenceTransformer('basel/ATTACK-BERT', device=self.device)
        self.mitre_df = self._load_mitre_detailed()
        self.mitre_embeddings = self.model.encode(
            self.mitre_df['description'].tolist(),
            batch_size=64,
            convert_to_numpy=True
        )
        print(f"✅ Loaded {len(self.mitre_df)} MITRE techniques")
    
    def _load_mitre_detailed(self) -> pd.DataFrame:
        """Load MITRE with detailed tactic mapping (COMPLETE 14 TACTICS)"""
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        data = requests.get(url).json()
        techniques = []
        
        tactic_map = {
            'reconnaissance': 'RECONNAISSANCE',
            'resource-development': 'RESOURCE_DEVELOPMENT',
            'initial-access': 'INITIAL_ACCESS',
            'execution': 'EXECUTION',
            'persistence': 'PERSISTENCE',
            'privilege-escalation': 'PRIVILEGE_ESCALATION',
            'defense-evasion': 'DEFENSE_EVASION',
            'credential-access': 'CREDENTIAL_ACCESS',
            'discovery': 'DISCOVERY',
            'lateral-movement': 'LATERAL_MOVEMENT',
            'collection': 'COLLECTION',
            'command-and-control': 'COMMAND_AND_CONTROL',
            'exfiltration': 'EXFILTRATION',
            'impact': 'IMPACT'
        }
        
        tactic_details = {
            'RECONNAISSANCE': 'Target research (Scan/Enumerate)',
            'RESOURCE_DEVELOPMENT': 'Build capabilities (Acquire infra)',
            'INITIAL_ACCESS': 'External system access (Phishing/Exploit)',
            'EXECUTION': 'Code execution (Scripting/RCE)',
            'PERSISTENCE': 'Maintain access (Services/Registry)',
            'PRIVILEGE_ESCALATION': 'Elevate privileges (UAC bypass)',
            'DEFENSE_EVASION': 'Avoid detection (Obfuscation)',
            'CREDENTIAL_ACCESS': 'Steal credentials (Dumpers)',
            'DISCOVERY': 'Reconnaissance (Enum users/domains)',
            'LATERAL_MOVEMENT': 'Move laterally (Pass-the-hash)',
            'COLLECTION': 'Gather data (Keylogging/Screen capture)',
            'COMMAND_AND_CONTROL': 'C2 communication (HTTP/DNS)',
            'EXFILTRATION': 'Data exfiltration (HTTP/DNS)',
            'IMPACT': 'Disrupt systems (Ransomware/Delete)'
        }
        
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern':
                refs = obj.get('external_references', [])
                mitre_id = next((r.get('external_id') for r in refs if r.get('source_name') == 'mitre-attack'), None)
                if mitre_id:
                    primary_tactic = None
                    for phase in obj.get('kill_chain_phases', []):
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            tactic_key = phase.get('phase_name', '').replace('-', '')
                            primary_tactic = tactic_map.get(tactic_key)
                            break
                    
                    if primary_tactic:
                        techniques.append({
                            'id': mitre_id,
                            'name': obj.get('name'),
                            'description': obj.get('description', '')[:300],
                            'tactic': primary_tactic,
                            'tactic_detail': tactic_details.get(primary_tactic, '')
                        })
        return pd.DataFrame(techniques)
    
    def build_cpe(self, row: pd.Series) -> str:
        part = {'a': 'a', 'o': 'o', 'h': 'h'}.get(str(row.get('part', 'a')).lower(), 'a')
        return f"cpe:2.3:{part}:{row['vendor']}:{row['product']}:{row['version']}:*:*:*:*:*:*:*"
    
    def get_nvd_cves_enhanced(self, cpe: str) -> List[Dict]:
        """NVD with FULL severity + vector parsing"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&resultsPerPage=10"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            
            cves = []
            for vuln in data.get('vulnerabilities', [])[:5]:
                cve = vuln['cve']
                metrics = cve.get('metrics', {})
                
                # Full CVSS extraction (SAFE)
                cvss_v3_metrics = metrics.get('cvssMetricV31', [])
                cvss_v4_metrics = metrics.get('cvssMetricV40', [])
                cvss_v2_metrics = metrics.get('cvssMetricV2', [])
                
                cvss_v3 = None
                if cvss_v3_metrics and len(cvss_v3_metrics) > 0:
                    cvss_v3 = cvss_v3_metrics[0].get('cvssData', {}).get('baseScore')
                
                cvss_v4 = None
                if cvss_v4_metrics and len(cvss_v4_metrics) > 0:
                    cvss_v4 = cvss_v4_metrics[0].get('cvssData', {}).get('baseScore')
                
                cvss_v2 = None
                if cvss_v2_metrics and len(cvss_v2_metrics) > 0:
                    cvss_v2 = cvss_v2_metrics[0].get('cvssData', {}).get('baseScore')
                
                # NVD SEVERITY from highest score
                base_score = max(filter(None, [cvss_v3, cvss_v4, cvss_v2]))
                nvd_severity = self._get_nvd_severity(base_score)
                nvd_severity_score = self._get_nvd_severity_score(nvd_severity)
                
                desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), '')[:400]
                
                cves.append({
                    'cve_id': cve['id'],
                    'description': desc,
                    'cvss_v3_raw': cvss_v3,
                    'cvss_v3_norm': cvss_v3/10.0 if cvss_v3 else None,
                    'cvss_v4_raw': cvss_v4,
                    'cvss_v4_norm': cvss_v4/10.0 if cvss_v4 else None,
                    'cvss_v2_raw': cvss_v2,
                    'cvss_v2_norm': cvss_v2/10.0 if cvss_v2 else None,
                    'nvd_severity': nvd_severity,
                    'nvd_severity_score': nvd_severity_score,
                    'published': cve.get('published'),
                    'last_modified': cve.get('lastModified')
                })
            return cves
        except Exception as e:
            print(f"❌ NVD Error: {e}")
            return []
    
    def _get_nvd_severity(self, base_score: float) -> str:
        if base_score is None:
            return 'NONE'
        elif base_score >= 9.0:
            return 'CRITICAL'
        elif base_score >= 7.0:
            return 'HIGH'
        elif base_score >= 4.0:
            return 'MEDIUM'
        elif base_score >= 0.1:
            return 'LOW'
        else:
            return 'NONE'
    
    def _get_nvd_severity_score(self, severity: str) -> float:
        return {
            'CRITICAL': 0.95, 'HIGH': 0.80, 'MEDIUM': 0.60, 
            'LOW': 0.30, 'NONE': 0.0
        }.get(severity, 0.0)
    
    def batch_mitre_detailed(self, descriptions: List[str]) -> List[List[Dict]]:
        """Detailed MITRE matching"""
        if not descriptions:
            return []
        
        embeddings = self.model.encode(descriptions, batch_size=32, convert_to_numpy=True)
        similarities = cosine_similarity(embeddings, self.mitre_embeddings)
        results = []
        
        for sims in similarities:
            top_idx = np.argsort(sims)[::-1][:5]
            matches = []
            for i in top_idx:
                if sims[i] > 0.22:
                    mitre_row = self.mitre_df.iloc[i]
                    matches.append({
                        'technique_id': mitre_row['id'],
                        'technique_name': mitre_row['name'][:50],
                        'tactic': mitre_row['tactic'],
                        'tactic_detail': mitre_row['tactic_detail'],
                        'similarity': float(sims[i])
                    })
            results.append(matches[:5])
        return results
    
    def process_asset(self, row: pd.Series) -> List[Dict]:
        cpe = self.build_cpe(row)
        vendor, product, version = row['vendor'], row['product'], row['version']
        
        cves = self.get_nvd_cves_enhanced(cpe)
        results = []
        
        for cve in cves:
            result = {
                'vendor': vendor,
                'product': product,
                'version': version,
                'cpe': cpe,
                'source': 'NVD',
                'cve_id': cve['cve_id'],
                'description': cve['description'],
                'cvss_v3_raw': cve['cvss_v3_raw'],
                'cvss_v3_norm': cve['cvss_v3_norm'],
                'cvss_v4_raw': cve['cvss_v4_raw'],
                'cvss_v4_norm': cve['cvss_v4_norm'],
                'cvss_v2_raw': cve['cvss_v2_raw'],
                'cvss_v2_norm': cve['cvss_v2_norm'],
                'nvd_severity': cve['nvd_severity'],
                'nvd_severity_score': cve['nvd_severity_score'],
                'published': cve['published'],
                'last_modified': cve['last_modified']
            }
            results.append(result)
        
        return results
    
    def run_pipeline(self, input_csv: str) -> pd.DataFrame:
        """Main pipeline execution"""
        start = time.time()
        df = pd.read_csv(input_csv)
        print(f"🚀 Threat Timeline: {len(df)} assets")
        
        all_results = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(self.process_asset, row) for _, row in df.iterrows()]
            for i, future in enumerate(as_completed(futures)):
                results = future.result()
                all_results.extend(results)
                print(f"Asset {i+1}: {len(results)} threats")
        
        # Batch MITRE mapping
        print("🧠 Mapping MITRE ATT&CK...")
        if all_results:
            descriptions = [r['description'] for r in all_results]
            mitre_results = self.batch_mitre_detailed(descriptions)
            
            for i, result in enumerate(all_results):
                mitres = mitre_results[i]
                result.update({
                    'attack_vector': mitres[0]['tactic'] if mitres else None,
                    'attack_vector_detail': mitres[0]['tactic_detail'] if mitres else None,
                    'mitre_top1': mitres[0]['technique_id'] if mitres else None,
                    'mitre_top1_name': mitres[0]['technique_name'] if mitres else None,
                    'mitre_top1_tactic': mitres[0]['tactic'] if mitres else None,
                    'mitre_top2': mitres[1]['technique_id'] if len(mitres) > 1 else None,
                    'mitre_top3': mitres[2]['technique_id'] if len(mitres) > 2 else None,
                })
        
        df_out = pd.DataFrame(all_results)
        elapsed = time.time() - start
        print(f"⚡ COMPLETE: {len(df_out)} threats in {elapsed:.1f}s")
        return df_out

    # Add this method to ThreatTimelinePipeline class
    def run_pipeline_csv(self, df_assets: pd.DataFrame) -> pd.DataFrame:
        """Streamlit-compatible version"""
        print(f"🚀 Processing {len(df_assets)} assets from DataFrame")

        all_results = []
        for i, (_, row) in enumerate(df_assets.iterrows()):
            results = self.process_asset(row)
            all_results.extend(results)
            print(f"Asset {i+1}: {len(results)} CVEs")

        # MITRE batch mapping
        descriptions = [r['description'] for r in all_results]
        mitre_results = self.batch_mitre_detailed(descriptions)

        for i, result in enumerate(all_results):
            mitres = mitre_results[i]
            if mitres:
                result.update({
                    'attack_vector': mitres[0]['tactic'],
                    'attack_vector_detail': mitres[0]['tactic_detail'],
                    'mitre_top1': mitres[0]['technique_id'],
                    'mitre_top1_name': mitres[0]['technique_name'],
                    'mitre_top1_tactic': mitres[0]['tactic'],
                })

        return pd.DataFrame(all_results)

    