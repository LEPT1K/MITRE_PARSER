# src/cross_linker.py (фрагменты, заменяющие старые методы)
import json
from pathlib import Path
from typing import Dict, List, Any
from normalizer import DataNormalizer
from config import Config

class CrossLinker:
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.capec: Dict[str, dict] = {}
        self.cwe: Dict[str, dict] = {}
        self.cve: Dict[str, dict] = {}
        self.attack: Dict[str, dict] = {}

    def load_databases(self) -> bool:
        """Загружает и НОРМАЛИЗУЕТ данные сразу"""
        try:
            for db_name, attr_name in [
                ("capec_database.json", "capec"),
                ("cwe_database.json", "cwe"),
                ("cve_database.json", "cve"),
                ("mitre_attack.json", "attack")
            ]:
                filepath = self.output_dir / db_name
                if not filepath.exists(): continue
                
                with open(filepath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                
                # 🔹 Нормализация перед загрузкой 🔹
                normalized = DataNormalizer.process_database(raw_data)
                setattr(self, attr_name, {item["id"]: item for item in normalized})
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки/нормализации: {e}")
            return False

    def _propagate_field(self, source_db: Dict, target_db: Dict, 
                         src_field: str, tgt_field: str, link_field: str):
        """Универсальный метод распространения данных между базами"""
        updated = 0
        for src_id, src_rec in source_db.items():
            links = src_rec.get(link_field, [])
            if not links: continue
            
            # Собираем данные из связанных записей
            values_to_add = []
            for link_id in links:
                if link_id in target_db:
                    val = target_db[link_id].get(tgt_field, "")
                    if isinstance(val, list):
                        values_to_add.extend(val)
                    elif isinstance(val, str) and val:
                        values_to_add.append(val)
            
            if values_to_add:
                # Объединяем, убираем дубли, берём топ-10
                current = src_rec.get(tgt_field, [])
                if isinstance(current, str): current = [current]
                merged = list(dict.fromkeys(current + values_to_add))[:10]
                if merged != current:
                    src_rec[tgt_field] = merged
                    updated += 1
        return updated

    def run(self) -> Dict[str, int]:
        print("\n🔗 Запуск двунаправленного связывания...")
        stats = {"capec": 0, "cwe": 0, "cve": 0, "attack": 0}
        
        # 1. CAPEC <-> ATT&CK (mitigations, related_*)
        stats["capec"] += self._propagate_field(self.attack, self.capec, 
            "related_capec", "mitigations", "related_capec")
        stats["capec"] += self._propagate_field(self.attack, self.capec,
            "related_capec", "detection", "related_capec")
            
        # 2. CWE <-> CVE (mitigations, detection)
        stats["cwe"] += self._propagate_field(self.cve, self.cwe,
            "related_cwe", "mitigation", "related_cwe")
        stats["cve"] += self._propagate_field(self.cwe, self.cve,
            "related_cwe", "mitigation", "related_cwe")
            
        # 3. CVE -> CAPEC -> ATT&CK (цепочка распространения)
        stats["cve"] += self._propagate_field(self.capec, self.cve,
            "related_capec", "mitigations", "related_capec")
        stats["attack"] += self._propagate_field(self.capec, self.attack,
            "related_mitre", "related_capec", "related_mitre")
            
        return stats

    def save_databases(self) -> bool:
        """Сохраняет с финальной нормализацией"""
        try:
            for db_name, data_dict in [
                ("capec_database.json", self.capec),
                ("cwe_database.json", self.cwe),
                ("cve_database.json", self.cve),
                ("mitre_attack.json", self.attack)
            ]:
                records = list(data_dict.values())
                with open(self.output_dir / db_name, "w", encoding="utf-8") as f:
                    json.dump(records, f, ensure_ascii=False, indent=2)
            print("✅ Все базы сохранены с заполненными полями")
            return True
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")
            return False