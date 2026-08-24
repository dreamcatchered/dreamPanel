#!/usr/bin/env python3
"""
Универсальный скрипт для исправления кодировки файлов.
Использует библиотеку ftfy для исправления mojibake и автоматически
удаляет лишние пустые строки.

Запуск:
    python fix_all_encoding.py           # Исправить все файлы
    python fix_all_encoding.py --dry-run  # Только проверить
"""

import os
import sys
from pathlib import Path
from ftfy import fix_text

TEXT_EXTENSIONS = {
    '.py', '.html', '.js', '.css', '.json', '.txt', '.md', '.env',
    '.sh', '.bash', '.yml', '.yaml', '.ini', '.cfg', '.conf',
    '.toml', '.rst', '.sql', '.xml'
}

SKIP_DIRS = {'__pycache__', '.git', 'node_modules', 'venv', '.venv', 'env', '.env', 'sessions'}
SKIP_FILES = {'fix_all_encoding.py', 'fix_encoding.py', 'cleanup_empty_lines.py'}


def should_skip_dir(dir_name):
    for pattern in SKIP_DIRS:
        if pattern.startswith('*') and pattern[1:] in dir_name:
            return True
        if dir_name == pattern:
            return True
    return False


def should_skip_file(file_name):
    return file_name in SKIP_FILES


def is_text_file(file_path):
    return file_path.suffix.lower() in TEXT_EXTENSIONS


def cleanup_empty_lines(content):
    """Удаляет лишние пустые строки (оставляет максимум 1 пустую подряд)."""
    lines = content.split('\n')
    result = []
    prev_empty = False
    
    for line in lines:
        if line.strip() == '':
            if not prev_empty:
                result.append('')
                prev_empty = True
        else:
            prev_empty = False
            result.append(line)
    
    return '\n'.join(result)


def fix_file(file_path, dry_run=False):
    """Исправляет кодировку и очищает файл от лишних пустых строк."""
    try:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()
        
        # Удаляем BOM
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            raw_bytes = raw_bytes[3:]
        
        # Декодируем как UTF-8
        try:
            content = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content = raw_bytes.decode('latin-1')
        
        original_content = content
        
        # Применяем ftfy для исправления mojibake
        content = fix_text(content)
        
        # Удаляем лишние пустые строки
        content = cleanup_empty_lines(content)
        
        # Проверяем, были ли изменения
        if content == original_content:
            return False
        
        if dry_run:
            print(f"  [CHECK] Будет исправлено: {file_path}")
            return True
        
        # Сохраняем с UTF-8 BOM для Windows
        with open(file_path, 'w', encoding='utf-8-sig') as f:
            f.write(content)
        
        print(f"  [OK] Исправлено: {file_path}")
        return True
            
    except Exception as e:
        print(f"  [ERROR] Ошибка: {file_path}: {e}")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Исправление кодировки файлов (ftfy + очистка пустых строк)'
    )
    parser.add_argument('path', nargs='?', default='.', help='Директория')
    parser.add_argument('--dry-run', action='store_true', help='Режим проверки')
    args = parser.parse_args()
    
    root_dir = Path(args.path).resolve()
    if not root_dir.exists():
        print(f"Ошибка: Директория не существует: {root_dir}")
        sys.exit(1)
    
    print("=" * 60)
    print("Исправление кодировки файлов")
    print(f"Директория: {root_dir}")
    print(f"Режим проверки: {'ДА' if args.dry_run else 'НЕТ'}")
    print()
    
    total = 0
    fixed = 0
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        
        for filename in filenames:
            if should_skip_file(filename):
                continue
            
            file_path = Path(dirpath) / filename
            if not is_text_file(file_path):
                continue
            
            total += 1
            if fix_file(file_path, dry_run=args.dry_run):
                if not args.dry_run:
                    fixed += 1
    
    print()
    print("=" * 60)
    print(f"Обработано файлов: {total}")
    print(f"Исправлено файлов: {fixed}")
    print("=" * 60)


if __name__ == '__main__':
    main()
