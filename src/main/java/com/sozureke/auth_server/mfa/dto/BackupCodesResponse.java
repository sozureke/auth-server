package com.sozureke.auth_server.mfa.dto;

import java.util.List;

public record BackupCodesResponse(List<String> backupCodes) {}
