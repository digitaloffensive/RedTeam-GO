@echo off
echo HL7 Security Tester
echo ====================
echo.
echo Usage examples:
echo.
echo   Full test (no TLS):
echo   hl7-security-tester.exe -host 10.0.0.5 -port 2575 -file sample_messages.hl7
echo.
echo   Full test (with TLS):
echo   hl7-security-tester.exe -host 10.0.0.5 -port 2575 -tls -file sample_messages.hl7
echo.
echo   Interactive mode:
echo   hl7-security-tester.exe -host 10.0.0.5 -port 2575 -file sample_messages.hl7 -interactive
echo.
echo   Help:
echo   hl7-security-tester.exe --help
echo.
pause
