#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для выборочного перевода полей в JSON-файлах MITRE Parser.
Запускать после генерации английских JSON.
"""
import json
import re
from pathlib import Path
from config import Config
from translator import Translator

# Поля, которые нужно перевести в каждом типе файла
FIELDS_TO_TRANSLATE = {
    "capec_database.json": ["mitigations", "prerequisites"],
    "cwe_database.json": ["mitigation"],
    "cve_database.json": ["mitigations"],
    "mitre_attack.json": ["mitigations", "detection"]
}

def translate_file(filepath: Path, fields: list, translator: Translator):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    updated = 0
    for item in data:
        for field in fields:
            if field in item:
                value = item[field]
                if isinstance(value, str):
                    translated = translator.translate(value)
                    if translated != value:
                        item[field] = translated
                        updated += 1
                elif isinstance(value, list):
                    new_list = []
                    for v in value:
                        if isinstance(v, str):
                            new_list.append(translator.translate(v))
                        else:
                            new_list.append(v)
                    item[field] = new_list
                    updated += 1
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ {filepath.name}: переведено элементов в полях {fields} — {updated}")

def main():
    print("🎯 Выборочный перевод полей JSON-файлов")
    translator = Translator()
    if not translator.enabled:
        print("❌ Перевод отключён в настройках. Установите ENABLE_TRANSLATION=True в config.py")
        return
    
    output_dir = Config.OUTPUT_DIR
    for filename, fields in FIELDS_TO_TRANSLATE.items():
        filepath = output_dir / filename
        if filepath.exists():
            translate_file(filepath, fields, translator)
        else:
            print(f"⚠️ Файл {filename} не найден, пропущен")
    
    print("🎉 Готово! Поля переведены.")

if __name__ == "__main__":
    main()