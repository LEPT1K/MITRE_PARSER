# src/cross_linker.py
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
                if not filepath.exists():
                    continue

                with open(filepath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)

                # Нормализация перед загрузкой
                normalized = DataNormalizer.process_database(raw_data)
                setattr(self, attr_name, {item["id"]: item for item in normalized})
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки/нормализации: {e}")
            return False

    def _propagate_field(self, source_db: Dict, target_db: Dict,
                         src_field: str, tgt_field: str, link_field: str) -> int:
        """
        Универсальный метод распространения данных:
        Берёт из source_db записи, у которых есть поле link_field (список ID).
        Для каждого ID находит запись в target_db и копирует значение поля tgt_field
        обратно в исходную запись (source_db) в поле tgt_field.
        """
        updated = 0
        for src_id, src_rec in source_db.items():
            links = src_rec.get(link_field, [])
            if not links:
                continue

            values_to_add = []
            for link_id in links:
                if link_id in target_db:
                    val = target_db[link_id].get(tgt_field, "")
                    if isinstance(val, list):
                        values_to_add.extend(val)
                    elif isinstance(val, str) and val:
                        values_to_add.append(val)

            if values_to_add:
                current = src_rec.get(tgt_field, [])
                if isinstance(current, str):
                    current = [current] if current else []
                merged = list(dict.fromkeys(current + values_to_add))
                merged = merged[:10]  # ограничиваем объём
                if merged != current:
                    src_rec[tgt_field] = merged
                    updated += 1
        return updated

    def _enrich_cve_from_cwe(self) -> int:
        """Обогащает CVE данными mitigations из связанных CWE"""
        updated = 0
        for cve_id, cve_rec in self.cve.items():
            cwe_ids = cve_rec.get("related_cwe", [])
            if not cwe_ids:
                continue

            mitigations = []
            for cwe_id in cwe_ids:
                if cwe_id in self.cwe:
                    mit = self.cwe[cwe_id].get("mitigation", "")
                    if mit:
                        mitigations.append(mit)

            if mitigations:
                existing = cve_rec.get("mitigations", [])
                if isinstance(existing, str):
                    existing = [existing] if existing else []
                combined = list(dict.fromkeys(existing + mitigations))[:10]
                if combined != existing:
                    cve_rec["mitigations"] = combined
                    # Удаляем устаревшее поле, если оно есть
                    cve_rec.pop("mitigation", None)
                    updated += 1
        return updated

    def _enrich_cwe_from_capec(self) -> int:
        """Обогащает CWE данными mitigations из связанных CAPEC"""
        updated = 0
        for cwe_id, cwe_rec in self.cwe.items():
            capec_ids = cwe_rec.get("related_capec", [])
            if not capec_ids:
                continue

            mitigations = []
            for capec_id in capec_ids:
                if capec_id in self.capec:
                    mits = self.capec[capec_id].get("mitigations", [])
                    if isinstance(mits, list):
                        mitigations.extend(mits)
                    elif isinstance(mits, str) and mits:
                        mitigations.append(mits)

            if mitigations:
                existing = cwe_rec.get("mitigation", "")
                new_mit = existing
                if existing:
                    new_mit += "\n\n" + "\n".join(mitigations)
                else:
                    new_mit = "\n".join(mitigations)
                if new_mit != existing:
                    cwe_rec["mitigation"] = new_mit
                    updated += 1
        return updated

    def _enrich_attack_related_capec_from_capec(self) -> int:
        """
        Заполняет related_capec в ATT&CK на основе related_mitre из CAPEC.
        Для каждой CAPEC с непустым related_mitre добавляет её ID в related_capec соответствующих техник ATT&CK.
        """
        updated = 0
        for capec_id, capec_rec in self.capec.items():
            attack_ids = capec_rec.get("related_mitre", [])
            if not attack_ids:
                continue
            for attack_id in attack_ids:
                if attack_id in self.attack:
                    attack_rec = self.attack[attack_id]
                    existing = attack_rec.get("related_capec", [])
                    if capec_id not in existing:
                        existing.append(capec_id)
                        attack_rec["related_capec"] = existing
                        updated += 1
        return updated

    def _enrich_cve_full_chain(self) -> int:
        """
        Цепочка обогащения CVE: CVE → CWE → CAPEC → ATT&CK
        Заполняет related_capec, related_mitre, mitigations.
        """
        updated = 0
        for cve_id, cve_rec in self.cve.items():
            cwe_ids = cve_rec.get("related_cwe", [])
            if not cwe_ids:
                continue

            related_capec = set()
            related_mitre = set()
            mitigations = set()

            for cwe_id in cwe_ids:
                cwe = self.cwe.get(cwe_id)
                if not cwe:
                    continue

                # CAPEC из CWE
                for capec_id in cwe.get("related_capec", []):
                    if capec_id in self.capec:
                        related_capec.add(capec_id)
                        capec = self.capec[capec_id]

                        # Mitigations из CAPEC
                        for mit in capec.get("mitigations", []):
                            mitigations.add(mit)

                        # ATT&CK из CAPEC (related_mitre)
                        for attack_id in capec.get("related_mitre", []):
                            if attack_id in self.attack:
                                related_mitre.add(attack_id)
                                # Mitigations из ATT&CK
                                for mit in self.attack[attack_id].get("mitigations", []):
                                    mitigations.add(mit)

            # Обновляем CVE
            if related_capec:
                cur_capec = set(cve_rec.get("related_capec", []))
                if not cur_capec.issuperset(related_capec):
                    cve_rec["related_capec"] = list(cur_capec | related_capec)
                    updated += 1

            if related_mitre:
                cur_mitre = set(cve_rec.get("related_mitre", []))
                if not cur_mitre.issuperset(related_mitre):
                    cve_rec["related_mitre"] = list(cur_mitre | related_mitre)
                    updated += 1

            if mitigations:
                cur_mit = set(cve_rec.get("mitigations", []))
                new_mit = cur_mit | mitigations
                if new_mit != cur_mit:
                    cve_rec["mitigations"] = list(new_mit)[:10]
                    cve_rec.pop("mitigation", None)   # убираем возможный дубликат
                    updated += 1

        return updated

    def run(self) -> Dict[str, int]:
        print("\n🔗 Запуск двунаправленного связывания...")
        stats = {"capec": 0, "cwe": 0, "cve": 0, "attack": 0}

        # 1. CAPEC ← ATT&CK (mitigations, detection)
        stats["capec"] += self._propagate_field(
            self.attack, self.capec,
            "related_capec", "mitigations", "related_capec"
        )
        stats["capec"] += self._propagate_field(
            self.attack, self.capec,
            "related_capec", "detection", "related_capec"
        )

        # 2. CWE ← CVE (mitigation)
        stats["cwe"] += self._propagate_field(
            self.cve, self.cwe,
            "related_cwe", "mitigation", "related_cwe"
        )

        # 3. Обогащение CVE из CWE (mitigations)
        stats["cve"] += self._enrich_cve_from_cwe()

        # 4. Обогащение CWE из CAPEC (mitigation)
        stats["cwe"] += self._enrich_cwe_from_capec()

        # 5. Обогащение ATT&CK: related_capec ← CAPEC.related_mitre
        stats["attack"] += self._enrich_attack_related_capec_from_capec()

        # 6. Обогащение ATT&CK из CAPEC (mitigations)
        stats["attack"] += self._propagate_field(
            self.capec, self.attack,
            "related_mitre", "mitigations", "related_mitre"
        )

        # 7. Полное обогащение CVE по цепочке CVE → CWE → CAPEC → ATT&CK
        stats["cve"] += self._enrich_cve_full_chain()

        print(f"📊 Статистика обогащения: {stats}")
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
                records = DataNormalizer.process_database(records)
                with open(self.output_dir / db_name, "w", encoding="utf-8") as f:
                    json.dump(records, f, ensure_ascii=False, indent=2)
            print("✅ Все базы сохранены с заполненными полями")
            return True
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")
            return False