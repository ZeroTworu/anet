#!/bin/bash

# Использовать find с дополнительными фильтрами
find . -type f \
    -not -path 'target*' \
    -not -path '*github*' \
    -not -path '*.lock*' \
    -not -path '*project*' \
    -not -path '*contrib*' \
    -not -path '*/\.*' \
    -not -name '.*' | sort | while read -r file; do

    echo "================================================"
    echo "Файл: $file"
    echo "================================================"

    # Проверить, является ли файл текстовым
    if file "$file" | grep -q text; then
        cat "$file"
    else
        echo "[Бинарный файл или файл неподдерживаемого формата]"
    fi

    echo -e "\n\n"
done
