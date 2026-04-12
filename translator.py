# src/translator.py
import re
import os
from pathlib import Path
from config import Config
from transformers import MarianMTModel, MarianTokenizer

# === НАСТРОЙКА ПУТИ КЭША (только латиница) ===
# Можете изменить на любой удобный путь без кириллицы
CACHE_DIR = str(Path(__file__).parent.parent / "hf_cache")
# Пример альтернативы: CACHE_DIR = "D:/huggingface_cache"
# ============================================

class Translator:
    """Локальный переводчик на базе Hugging Face MarianMT с указанием кэш-директории"""

    def __init__(self, target_lang: str = None):
        self.enabled = Config.ENABLE_TRANSLATION
        self.target_lang = target_lang or Config.TRANSLATE_TO
        self.model_name = f"Helsinki-NLP/opus-mt-en-{self.target_lang}"
        self.cache_dir = CACHE_DIR

        if self.enabled:
            try:
                print(f"🌐 Загрузка модели перевода {self.model_name}...")
                print(f"   Кэш-директория: {self.cache_dir}")
                self.tokenizer = MarianTokenizer.from_pretrained(
                    self.model_name,
                    cache_dir=self.cache_dir
                )
                self.model = MarianMTModel.from_pretrained(
                    self.model_name,
                    cache_dir=self.cache_dir
                )
                print("✅ Модель загружена")
            except Exception as e:
                print(f"❌ Ошибка загрузки модели: {e}")
                self.enabled = False

        self._cache = {}
        self._cache_file = Config.OUTPUT_DIR / "translate_cache.json"
        self._load_cache()

    def _load_cache(self):
        if self._cache_file.exists():
            try:
                import json
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
                print(f"📦 Загружено {len(self._cache)} переводов из кэша")
            except:
                pass

    def _save_cache(self):
        try:
            import json
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=2)
        except:
            pass

    def translate(self, text: str, use_cache: bool = True) -> str:
        if not self.enabled:
            return text
        if not text or not isinstance(text, str):
            return text
        text = text.strip()
        if not text or self._is_russian(text):
            return text
        if re.match(r'^(CAPEC|CWE|CVE|T\d{4}(\.\d{3})?|[A-Z]{2,}-\d+)$', text):
            return text
        if use_cache and text in self._cache:
            return self._cache[text]

        try:
            inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True)
            translated = self.model.generate(**inputs)
            result = self.tokenizer.decode(translated[0], skip_special_tokens=True)
            self._cache[text] = result
            return result
        except Exception as e:
            print(f"⚠️ Ошибка перевода: {e}")
            return text

    def translate_list(self, items: list) -> list:
        if not self.enabled or not items:
            return items
        return [self.translate(item) if isinstance(item, str) else item for item in items]

    def translate_batch(self, texts: list) -> list:
        return self.translate_list(texts)

    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))

    def __del__(self):
        if hasattr(self, '_cache'):
            self._save_cache()