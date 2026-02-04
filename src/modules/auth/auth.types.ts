export interface User {
    id: string;
    email: string;
    password_hash: string;
    email_verified: boolean;
    verification_token?: string | null;
    verification_token_expires_at?: Date | null;
    reset_password_token?: string | null;
    reset_password_token_expires_at?: Date | null;
    created_at: Date;
    updated_at: Date;
    last_login_at?: Date | null;
}

export interface UserWithoutPassword extends Omit<User, 'password_hash' | 'verification_token' | 'reset_password_token'> { }

export interface RefreshToken {
    id: string;
    user_id: string;
    token_hash: string;
    expires_at: Date;
    created_at: Date;
    revoked_at?: Date | null;
    user_agent?: string | null;
    ip_address?: string | null;
}

export interface JWTPayload {
    userId: string;
    email: string;
    iat?: number;
    exp?: number;
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}

export interface RegisterDTO {
    email: string;
    password: string;
}

export interface LoginDTO {
    email: string;
    password: string;
}

export interface RefreshTokenDTO {
    refreshToken: string;
}

export interface ResetPasswordDTO {
    token: string;
    newPassword: string;
}

export interface RequestPasswordResetDTO {
    email: string;
}

export interface VerifyEmailDTO {
    token: string;
}

export interface OAuthConnection {
    id: string;
    user_id: string;
    service: string;
    service_user_id?: string | null;
    encrypted_access_token: string;
    encrypted_refresh_token?: string | null;
    token_iv: string;
    token_auth_tag: string;
    token_type: string;
    expires_at?: Date | null;
    scope?: string | null;
    created_at: Date;
    updated_at: Date;
    last_synced_at?: Date | null;
}

export interface DecryptedTokens {
    accessToken: string;
    refreshToken?: string;
}

export interface OAuthCallbackParams {
    code: string;
    state: string;
    error?: string;
    error_description?: string;
}

export interface OAuthTokenResponse {
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string;
}

// Request types with user attached
export interface AuthenticatedRequest extends Request {
    user?: JWTPayload;
}