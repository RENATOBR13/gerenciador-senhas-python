@echo off
echo ==========================================
echo    Compilando o Gerenciador de Senhas...
echo ==========================================

:: Executa a compilação via PyInstaller usando o interpretador Python
python -m PyInstaller --noconsole --onefile gui.py

echo.
echo ==========================================
echo    Processo finalizado!
echo    Verifique a pasta 'dist' para o seu .exe.
echo ==========================================
pause