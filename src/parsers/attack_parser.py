# src/parsers/attack_parser.py
import json
import re
import html
from collections import defaultdict
from config import Config
from parsers.base import BaseParser


class ATTCKParser(BaseParser):
    """Парсер MITRE ATT&CK с полным разрешением STIX-графов"""

    def parse(self, json_content: bytes) -> list:
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            print(f"❌ Ошибка парсинга ATT&CK JSON: {e}")
            return []

        objects = data.get("objects", [])
        obj_map = {obj["id"]: obj for obj in objects if "id" in obj}
        
        # Индекс связей: technique_id -> [mitigation_ids]
        mitigates_map = defaultdict(list)
        for obj in objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
                src = obj.get("source_ref")
                tgt = obj.get("target_ref")
                if src and tgt:
                    mitigates_map[src].append(tgt)

        techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
        print(f"🔍 Найдено техник ATT&CK: {len(techniques)}")

        limit = Config.MAX_ATTACK_RECORDS
        if limit and limit > 0 and len(techniques) > limit:
            techniques = techniques[:limit]
            print(f"⏱️ Лимит: обрабатываем {limit}/{len(techniques)} записей")

        results = []
        for idx, tech in enumerate(techniques):
            item = self._parse_technique(tech, obj_map, mitigates_map)
            if item:
                results.append(item)
            if (idx + 1) % 100 == 0:
                print(f"  📊 Обработано: {idx + 1}/{len(techniques)}")

        print(f"📊 Итого записей ATT&CK: {len(results)}")
        return results

    def _parse_technique(self, tech: dict, obj_map: dict, mit_map: dict) -> dict | None:
        try:
            tech_id = tech.get("id", "")
            ext_refs = tech.get("external_references", [])
            
            # Извлекаем MITRE ID (T1234 или T1234.001)
            mitre_id = next(
                (ref.get("external_id", "") for ref in ext_refs if ref.get("source_name") == "mitre-attack"), 
                ""
            )
            if not mitre_id:
                return None

            # === CWE & CAPEC ===
            related_cwe, related_capec = [], []
            for ref in ext_refs:
                src = ref.get("source_name", "").lower()
                ext_id = ref.get("external_id", "")
                if ext_id:
                    if "cwe" in src:
                        related_cwe.append(f"CWE-{ext_id}" if not ext_id.startswith("CWE-") else ext_id)
                    elif "capec" in src:
                        related_capec.append(f"CAPEC-{ext_id}" if not ext_id.startswith("CAPEC-") else ext_id)

            # === Mitigations (разрешение через relationship -> course-of-action) ===
            raw_mitigs = []
            for m_id in mit_map.get(tech_id, []):
                if m_id in obj_map:
                    m_obj = obj_map[m_id]
                    text = m_obj.get("description") or m_obj.get("name", "")
                    text = self._clean_html(text)
                    if text and len(text) > 15:
                        # MITRE разделяет меры защиты двойными переносами строк
                        for line in text.split("\n\n"):
                            line = line.strip()
                            if line:
                                raw_mitigs.append(line)

            # Fallback: если у подтехники нет mitigations, пробуем взять от родителя (TXXXX)
            if not raw_mitigs and "." in mitre_id:
                parent_id = mitre_id.split(".")[0]
                # Ищем ID родительской техники в obj_map по external_id
                parent_stix_id = next((oid for oid, obj in obj_map.items() 
                                     if obj.get("type") == "attack-pattern" and 
                                     any(r.get("external_id") == parent_id for r in obj.get("external_references", []))), None)
                if parent_stix_id:
                    raw_mitigs = []
                    for m_id in mit_map.get(parent_stix_id, []):
                        if m_id in obj_map:
                            text = obj_map[m_id].get("description") or obj_map[m_id].get("name", "")
                            text = self._clean_html(text)
                            if text and len(text) > 15:
                                for line in text.split("\n\n"):
                                    if line.strip():
                                        raw_mitigs.append(line.strip())

            # === Detection ===
            detection = self._clean_html(tech.get("x_mitre_detection", ""))
            if not detection and "." in mitre_id:
                # Fallback detection от родителя
                parent_id = mitre_id.split(".")[0]
                parent_stix_id = next((oid for oid, obj in obj_map.items() 
                                     if obj.get("type") == "attack-pattern" and 
                                     any(r.get("external_id") == parent_id for r in obj.get("external_references", []))), None)
                if parent_stix_id:
                    detection = self._clean_html(obj_map.get(parent_stix_id, {}).get("x_mitre_detection", ""))

            # === Базовые поля ===
            platforms = tech.get("x_mitre_platforms", [])
            phases = tech.get("kill_chain_phases", [])
            tactic = phases[0].get("phase_name", "").replace("-", " ").title() if phases else ""
            desc = self._clean_html(tech.get("description", ""))

            item = {
                "id": mitre_id,
                "name": tech.get("name", "").strip(),
                "tactic": tactic,
                "description": desc,
                "platforms": platforms,
                "related_cwe": related_cwe,
                "related_capec": related_capec,
                "requires_service": self._extract_services(platforms, desc),
                "detection": detection,
                "mitigations": raw_mitigs
            }

            # === Перевод ===
            if Config.ENABLE_TRANSLATION:
                for field in ["name", "description", "tactic", "detection"]:
                    if item[field] and not self._is_russian(item[field]):
                        item[field] = self.translator.translate(item[field])
                item["mitigations"] = self.translator.translate_list(item["mitigations"])
                item["platforms"] = self.translator.translate_list(item["platforms"])

            # === Финальная очистка (убираем пробелы в ключах и значениях) ===
            return {k.strip(): v.strip() if isinstance(v, str) else [x.strip() if isinstance(x, str) else x for x in v] if isinstance(v, list) else v for k, v in item.items()}

        except Exception as e:
            print(f"⚠️ Ошибка парсинга техники {tech.get('id', 'UNKNOWN')}: {e}")
            return None

    def _clean_html(self, text: str) -> str:
        """Удаляет HTML-теги и декодирует спецсимволы"""
        if not text:
            return ""
        clean = re.sub(r'<[^>]+>', ' ', text)
        clean = re.sub(r'\s+', ' ', clean)
        return html.unescape(clean).strip()

    def _extract_services(self, platforms: list, description: str) -> list:
        services = set()
        plat_map = {"windows": "windows_os", "linux": "linux_os", "macos": "macos_os", 
                    "azure ad": "cloud_identity", "office 365": "office365"}
        for p in platforms:
            pl = p.lower()
            for k, v in plat_map.items():
                if k in pl: services.add(v)
                
        svc_map = {"web server": "web_server", "database": "database", "active directory": "active_directory",
                   "ssh": "ssh", "rdp": "rdp", "smb": "smb", "powershell": "powershell", "api": "api_service"}
        desc_l = description.lower()
        for k, v in svc_map.items():
            if k in desc_l: services.add(v)
        return list(services)

    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))