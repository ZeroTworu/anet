# Настройки
$outputFile = "project_report.txt"
$exclude = @(
    "*target*", "*github*", "*.lock*", "*project*", "*android-build*", 
    "LICENSE.md", "README.md", "free_ai.md", "*node_modules*", 
    "CoC.md", "*dist*", ".*", "project_report.txt" # Исключаем и сам файл отчета
)

# Удаляем старый файл отчета, если он есть
if (Test-Path $outputFile) { Remove-Item $outputFile }

# Получаем список файлов
$files = Get-ChildItem -Recurse -File -Exclude $exclude | Where-Object { 
    $_.FullName -notmatch "(\\|\/)\." 
} | Sort-Object FullName

# Обработка файлов
foreach ($file in $files) {
    # Записываем заголовок в файл
    Add-Content $outputFile "================================================"
    Add-Content $outputFile "Файл: $($file.FullName)"
    Add-Content $outputFile "================================================"
    
    # Пытаемся прочитать файл. 
    # Если это бинарный файл, Get-Content может выбросить ошибку или вернуть мусор,
    # поэтому мы используем простую проверку на ошибки.
    try {
        $content = Get-Content $file.FullName -Raw -ErrorAction Stop
        Add-Content $outputFile $content
    }
    catch {
        Add-Content $outputFile "[Бинарный файл или ошибка чтения]"
    }

    # Добавляем пустые строки для разделения
    Add-Content $outputFile "`n`n"
    
    Write-Host "Обработан: $($file.Name)" # Вывод в консоль для контроля прогресса
}

Write-Host "Готово! Отчет сохранен в файл: $outputFile"