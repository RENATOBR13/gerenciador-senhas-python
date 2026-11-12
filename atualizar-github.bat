@echo off
echo ==========================================
echo    Atualizando o Repositorio no GitHub...
echo ==========================================

:: Adiciona todos os arquivos modificados
git add .

:: Pergunta qual foi a alteracao para usar na mensagem do commit
set /p mensagem="Digite a mensagem do commit (o que foi alterado): "

:: Realiza o commit com a mensagem informada
git commit -m "%mensagem%"

:: Envia para o GitHub na branch master (altere para main se necessario)
git push origin master

echo.
echo ==========================================
echo    Processo finalizado com sucesso!
echo ==========================================
pause