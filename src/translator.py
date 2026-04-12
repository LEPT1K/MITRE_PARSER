# src/translator.py
from deep_translator import GoogleTranslator
import re
import time
from pathlib import Path
from config import Config  # ← Импорт конфига

class Translator:
    """Переводчик с поддержкой включения/отключения"""
    
    def __init__(self, target_lang: str = None, delay: float = None):
        # Используем настройки из Config, если не переданы явно
        self.enabled = Config.ENABLE_TRANSLATION
        self.target_lang = target_lang or Config.TRANSLATE_TO
        self.delay = delay if delay is not None else Config.TRANSLATION_DELAY
        
        if self.enabled:
            try:
                self.translator = GoogleTranslator(source="auto", target=self.target_lang)
                print(f"🌐 Переводчик включён → {self.target_lang}")
            except Exception as e:
                print(f"⚠️ Не удалось инициализировать переводчик: {e}")
                self.enabled = False
        else:
            #print("⚡ Перевод отключён (быстрый режим)")
            self.translator = None
        
        self._cache = {}
        self._cache_file = Config.OUTPUT_DIR / "translate_cache.json"
        self._load_cache()
        self._request_count = 0
    
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
        # 🔹 Если перевод отключён — возвращаем оригинал
        if not self.enabled:
            return text
        
        if not text or not isinstance(text, str):
            return text
        
        text = text.strip()
        if not text:
            return text
            
        # Пропускаем технические идентификаторы
        if re.match(r'^(CAPEC|CWE|CVE|T\d{4}(\.\d{3})?|[A-Z]{2,}-\d+)$', text):
            return text
        
        # Проверяем кэш
        if use_cache and text in self._cache:
            return self._cache[text]
        
        # Проверяем, не на русском ли уже
        if self._is_russian(text):
            return text
        
        try:
            # Задержка перед запросом
            if self._request_count > 0 and self.delay > 0:
                time.sleep(self.delay)
            
            result = self.translator.translate(text)
            self._cache[text] = result
            self._request_count += 1
            
            # Сохраняем кэш периодически
            if self._request_count % 50 == 0:
                self._save_cache()
                print(f"  💾 Кэш сохранён ({self._request_count} переводов)")
            
            return result
            
        except Exception as e:
            print(f"⚠️ Ошибка перевода '{text[:40]}...': {e}")
            return text
    
    def translate_list(self, items: list, use_cache: bool = True) -> list:
        if not self.enabled:
            return items
        
        if not items:
            return []
        
        result = []
        total = len(items)
        for idx, item in enumerate(items):
            if item and isinstance(item, str):
                result.append(self.translate(item, use_cache))
                if total > 10 and (idx + 1) % 10 == 0:
                    print(f"    🔄 Перевод: {idx + 1}/{total}")
            else:
                result.append(item)
        return result
    
    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))