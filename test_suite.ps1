$base = "http://localhost:8000"

Write-Host "=== TEST 1: AI Assistant ===" -ForegroundColor Cyan
$aiResult = Invoke-RestMethod "$base/ask-ai" -Method POST -ContentType "application/json" -Body '{"message":"what is phishing attack?"}'
Write-Host "Reply: $($aiResult.reply.Substring(0, [Math]::Min(120, $aiResult.reply.Length)))..." -ForegroundColor Green
Write-Host ""

Write-Host "=== TEST 2: URL Scanner ===" -ForegroundColor Cyan
$urlResult = Invoke-RestMethod "$base/scan-url" -Method POST -ContentType "application/json" -Body '{"url":"http://secure-bank-login-example.com"}'
Write-Host "Score: $($urlResult.score) | Verdict: $($urlResult.verdict)" -ForegroundColor Yellow
Write-Host "Findings: $($urlResult.findings -join ', ')"
Write-Host ""

Write-Host "=== TEST 3: SMS Detector ===" -ForegroundColor Cyan
$smsResult = Invoke-RestMethod "$base/analyze-sms" -Method POST -ContentType "application/json" -Body '{"body":"URGENT: Your account is locked. Provide OTP to verify at http://paypal.xyz"}'
Write-Host "Score: $($smsResult.score) | Verdict: $($smsResult.verdict)" -ForegroundColor Yellow
Write-Host "Findings: $($smsResult.findings -join ', ')"
Write-Host ""

Write-Host "=== TEST 4: Email Analyzer ===" -ForegroundColor Cyan
$emailResult = curl.exe -s -X POST "$base/analyze-email" `
  -F "sender=support@paypal-security.xyz" `
  -F "subject=URGENT: Your account is suspended" `
  -F "body=Dear Customer, your account has been suspended. Verify immediately. Click: http://paypal-login.xyz/verify?otp=reset. Share your OTP now." | ConvertFrom-Json
Write-Host "Overall Score: $($emailResult.overall_score) | Verdict: $($emailResult.verdict)" 
Write-Host "Findings: $($emailResult.email.findings -join '; ')"
Write-Host ""

Write-Host "=== TEST 5: QR Scanner ===" -ForegroundColor Cyan
$emptyQrResult = curl.exe -s -X POST "$base/scan/qr" -F "file=@requirements.txt" | ConvertFrom-Json
Write-Host "Decoded: $($emptyQrResult.decoded) | Message: $($emptyQrResult.message)"
Write-Host ""

Write-Host "=== TEST 6: Network IDS ===" -ForegroundColor Cyan
$ids = Invoke-RestMethod "$base/ids-status" -Method GET
Write-Host "Engine: $($ids.engine) | Status: $($ids.status)" -ForegroundColor Green
Write-Host "Alerts: $($ids.alerts.Count)"
Write-Host ""

Write-Host "=== ALL TESTS COMPLETE ===" -ForegroundColor Cyan
