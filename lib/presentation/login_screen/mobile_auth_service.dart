import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

/// Handles Supabase initialization
class SupabaseService {
  static final SupabaseService _instance = SupabaseService._internal();
  factory SupabaseService() => _instance;
  SupabaseService._internal();

  SupabaseClient get client => Supabase.instance.client;

  static Future<void> initialize() async {
    await Supabase.initialize(
      url: dotenv.env['SUPABASE_URL']!,
      anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
    );
  }
}

/// Production-ready authentication service with 2Factor OTP
class MobileAuthService {
  static final MobileAuthService _instance = MobileAuthService._internal();
  factory MobileAuthService() => _instance;
  MobileAuthService._internal();

  static const String _sessionKey = 'supabase_session';
  static const String _userKey = 'user_data';

  Session? _session;
  Map<String, dynamic>? _currentUser;

  /// Initialize auth service: restore saved session if available
  Future<void> initialize() async {
    final prefs = await SharedPreferences.getInstance();
    final sessionJson = prefs.getString(_sessionKey);
    final userJson = prefs.getString(_userKey);

    debugPrint('=== INITIALIZING AUTH SERVICE ===');

    if (sessionJson != null && userJson != null) {
      try {
        final sessionData = jsonDecode(sessionJson);
        final userData = jsonDecode(userJson);

        debugPrint('Found stored session for user: ${userData['id']}');

        // Create session object from stored data
        final user = User.fromJson(sessionData['user']);

        _session = Session(
          accessToken: sessionData['access_token'],
          refreshToken: sessionData['refresh_token'],
          expiresIn: sessionData['expires_in'] ?? 3600,
          tokenType: sessionData['token_type'] ?? 'bearer',
          user: user,
        );
        _currentUser = userData;

        // Set the session in Supabase client
        try {
          final sessionString = jsonEncode({
            'access_token': _session!.accessToken,
            'refresh_token': _session!.refreshToken,
            'expires_in': _session!.expiresIn,
            'expires_at': _session!.expiresAt,
            'token_type': _session!.tokenType,
            'user': _session!.user.toJson(),
          });

          await SupabaseService().client.auth.recoverSession(sessionString);
          debugPrint('✅ Successfully restored Supabase session');
          debugPrint('Current user ID: ${SupabaseService().client.auth.currentUser?.id}');

          // Verify the session is still valid
          await _verifySessionValidity();
        } catch (e) {
          debugPrint('❌ Failed to restore Supabase session: $e');
          final refreshed = await refreshSession();
          if (!refreshed) {
            debugPrint('Session refresh failed, clearing invalid session');
            await _clearSession();
          }
        }
      } catch (e) {
        debugPrint('❌ Failed to parse stored session: $e');
        await _clearSession();
      }
    } else {
      debugPrint('No stored session found');
    }

    debugAuthState();
    debugPrint('=== AUTH INITIALIZATION COMPLETE ===');
  }

  /// Verify if the current session is valid
  Future<bool> _verifySessionValidity() async {
    try {
      final response = await SupabaseService().client
          .from('user_profiles')
          .select('id')
          .eq('id', _currentUser?['id'])
          .maybeSingle();

      debugPrint('✅ Session validation successful');
      return true;
    } catch (e) {
      debugPrint('❌ Session validation failed: $e');
      return false;
    }
  }

  /// Store Supabase session locally
  Future<void> _storeSession(Map<String, dynamic> authResponse) async {
    final prefs = await SharedPreferences.getInstance();

    // Store session data
    final sessionData = {
      'access_token': authResponse['accessToken'],
      'refresh_token': authResponse['refreshToken'],
      'expires_in': 3600,
      'expires_at': authResponse['expiresAt'],
      'token_type': authResponse['tokenType'] ?? 'bearer',
      'user': {
        'id': authResponse['auth_user_id'],
        'email': authResponse['user']['email'],
        'phone': authResponse['user']['mobile_number'],
        'user_metadata': {
          'mobile_number': authResponse['user']['mobile_number'],
          'mobile_verified': true,
          'auth_method': 'mobile_otp'
        },
        'app_metadata': {
          'provider': 'phone',
          'providers': ['phone']
        }
      }
    };

    await prefs.setString(_sessionKey, jsonEncode(sessionData));
    await prefs.setString(_userKey, jsonEncode(authResponse['user']));

    // Create Session object
    final user = User.fromJson(sessionData['user']);

    _session = Session(
      accessToken: authResponse['accessToken'],
      refreshToken: authResponse['refreshToken'],
      expiresIn: 3600,
      tokenType: authResponse['tokenType'] ?? 'bearer',
      user: user,
    );
    _currentUser = authResponse['user'];

    debugPrint('✅ Stored session for user: ${_currentUser?['id']}');
  }

  /// Clear stored session and sign out from Supabase
  Future<void> _clearSession() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_sessionKey);
    await prefs.remove(_userKey);

    _session = null;
    _currentUser = null;

    try {
      await SupabaseService().client.auth.signOut();
    } catch (e) {
      debugPrint('Error during signOut: $e');
    }

    debugPrint('🗑️ Cleared all session data');
  }

  /// Send OTP via 2Factor API (Production)
  Future<OtpResponse> sendOtp(String mobileNumber) async {
    try {
      final phoneNumber = '+91${mobileNumber.replaceAll(RegExp(r'[^\d]'), '')}';
      debugPrint('📱 Sending OTP to: $phoneNumber');

      final response = await SupabaseService().client.functions.invoke(
        'mobile-auth',
        body: {
          'action': 'request-otp',
          'mobile_number': phoneNumber,
          'device_fingerprint': await _getDeviceFingerprint(),
        },
      );

      debugPrint('Response Status: ${response.status}');
      debugPrint('Response Data: ${response.data}');

      if (response.status == 200 &&
          response.data is Map &&
          response.data['success'] == true) {
        return OtpResponse(
          success: true,
          message: response.data['message'] ?? 'OTP sent successfully',
          sessionId: response.data['sessionId'],
        );
      }

      // Handle error response
      final errorMessage = response.data is Map 
          ? response.data['message'] ?? 'Failed to send OTP'
          : 'Failed to send OTP';
      
      throw MobileAuthException(errorMessage);
    } catch (e) {
      debugPrint('❌ Send OTP Error: $e');
      if (e is MobileAuthException) rethrow;
      throw MobileAuthException('Network error. Please check your connection.');
    }
  }

  /// Verify OTP via 2Factor API (Production)
  Future<AuthResponse> verifyOtp(String mobileNumber, String otp) async {
    try {
      final phoneNumber = '+91${mobileNumber.replaceAll(RegExp(r'[^\d]'), '')}';
      debugPrint('🔐 Verifying OTP for: $phoneNumber');

      final response = await SupabaseService().client.functions.invoke(
        'mobile-auth',
        body: {
          'action': 'verify-otp',
          'mobile_number': phoneNumber,
          'otp': otp,
          'device_fingerprint': await _getDeviceFingerprint(),
        },
      );

      debugPrint('Verify Response Status: ${response.status}');
      debugPrint('Verify Response Data: ${response.data}');

      if (response.status == 200 &&
          response.data is Map &&
          response.data['success'] == true) {
        final data = response.data;

        // Validate that we received real tokens
        if (data['accessToken'] == null || data['refreshToken'] == null) {
          throw MobileAuthException('Invalid response: missing authentication tokens');
        }

        // Store the session with real tokens
        await _storeSession(data);

        // Set the session in Supabase client immediately
        try {
          final sessionString = jsonEncode({
            'access_token': data['accessToken'],
            'refresh_token': data['refreshToken'],
            'expires_in': 3600,
            'expires_at': data['expiresAt'],
            'token_type': data['tokenType'] ?? 'bearer',
            'user': _session!.user.toJson(),
          });

          await SupabaseService().client.auth.recoverSession(sessionString);
          debugPrint('✅ Successfully set Supabase session after login');
        } catch (e) {
          debugPrint('⚠️ Warning: Could not set Supabase session: $e');
        }

        debugAuthState();

        return AuthResponse(
          success: true,
          user: data['user'],
          message: data['message'] ?? 'Login successful',
        );
      }

      // Handle error response
      final errorMessage = response.data is Map 
          ? response.data['message'] ?? 'Invalid OTP'
          : 'Invalid OTP';
      
      throw MobileAuthException(errorMessage);
    } catch (e) {
      debugPrint('❌ Verify OTP Error: $e');
      if (e is MobileAuthException) rethrow;
      throw MobileAuthException('Verification failed. Please try again.');
    }
  }

  /// Refresh session using edge function
  Future<bool> refreshSession() async {
    if (_session == null || _session!.refreshToken?.isEmpty == true) {
      debugPrint('No session to refresh');
      return false;
    }

    try {
      debugPrint('🔄 Attempting to refresh session...');

      final response = await SupabaseService().client.functions.invoke(
        'mobile-auth',
        body: {
          'action': 'refresh-session',
          'user_id': _session!.user.id,
          'refreshToken': _session!.refreshToken,
        },
      );

      debugPrint('Refresh response: ${response.data}');

      if (response.status == 200 &&
          response.data is Map &&
          response.data['success'] == true) {
        final data = response.data;

        if (data['accessToken'] != null && data['refreshToken'] != null) {
          final prefs = await SharedPreferences.getInstance();
          final sessionData = {
            'access_token': data['accessToken'],
            'refresh_token': data['refreshToken'],
            'expires_in': 3600,
            'expires_at': data['expiresAt'],
            'token_type': 'bearer',
            'user': _session!.user.toJson(),
          };

          await prefs.setString(_sessionKey, jsonEncode(sessionData));

          _session = Session(
            accessToken: data['accessToken'],
            refreshToken: data['refreshToken'],
            expiresIn: 3600,
            tokenType: 'bearer',
            user: _session!.user,
          );

          try {
            await SupabaseService().client.auth.recoverSession(jsonEncode(sessionData));
            debugPrint('✅ Session refreshed successfully');
          } catch (e) {
            debugPrint('⚠️ Warning: Could not update Supabase session: $e');
          }
        }

        return true;
      }

      debugPrint('❌ Session refresh failed');
      await _clearSession();
      return false;
    } catch (e) {
      debugPrint('❌ Refresh session error: $e');
      await _clearSession();
      return false;
    }
  }

  /// Get device fingerprint for session tracking
  Future<String> _getDeviceFingerprint() async {
    return 'flutter_${DateTime.now().millisecondsSinceEpoch % 100000}';
  }

  // Getters
  bool get isAuthenticated {
    final hasLocalSession = _session != null && _currentUser != null;
    final hasSupabaseUser = SupabaseService().client.auth.currentUser != null;
    final hasSupabaseSession = SupabaseService().client.auth.currentSession != null;

    return hasLocalSession && hasSupabaseUser && hasSupabaseSession;
  }

  bool get isSupabaseAuthenticated {
    return SupabaseService().client.auth.currentUser != null &&
           SupabaseService().client.auth.currentSession != null;
  }

  Map<String, dynamic>? get currentUser => _currentUser;
  String? get userId => _currentUser?['id'];
  Session? get currentSession => _session;

  /// Ensure valid session before making authenticated requests
  Future<bool> ensureValidSession() async {
    debugPrint('=== ENSURING VALID SESSION ===');

    final currentUser = SupabaseService().client.auth.currentUser;
    final currentSession = SupabaseService().client.auth.currentSession;

    if (currentUser == null || currentSession == null) {
      debugPrint('No valid session, attempting refresh');
      return await refreshSession();
    }

    // Check if token is close to expiry (refresh if less than 5 minutes left)
    if (currentSession.expiresAt != null) {
      final expiresAt = DateTime.fromMillisecondsSinceEpoch(currentSession.expiresAt! * 1000);
      final now = DateTime.now();
      final minutesUntilExpiry = expiresAt.difference(now).inMinutes;

      if (minutesUntilExpiry < 5) {
        debugPrint('Token expires soon, refreshing');
        return await refreshSession();
      }
    }

    debugPrint('✅ Session is valid');
    return true;
  }

  /// Debug authentication state
  void debugAuthState() {
    final supabaseUser = SupabaseService().client.auth.currentUser;
    final supabaseSession = SupabaseService().client.auth.currentSession;

    debugPrint('=== AUTH STATE DEBUG ===');
    debugPrint('Local session: ${_session != null}');
    debugPrint('Local user: ${_currentUser != null}');
    debugPrint('Local user ID: ${_currentUser?['id']}');
    debugPrint('Supabase user: ${supabaseUser != null}');
    debugPrint('Supabase user ID: ${supabaseUser?.id}');
    debugPrint('Supabase session: ${supabaseSession != null}');
    debugPrint('isAuthenticated: $isAuthenticated');
    debugPrint('========================');
  }

  /// Get current access token
  String? get currentAccessToken {
    final supabaseSession = SupabaseService().client.auth.currentSession;
    return supabaseSession?.accessToken ?? _session?.accessToken;
  }

  /// Logout
  Future<void> logout() async {
    debugPrint('🚪 Logging out user...');
    await _clearSession();
    debugPrint('✅ Logout complete');
  }

  /// Utility methods
  static String formatMobileNumber(String mobile) {
    final clean = mobile.replaceAll(RegExp(r'[^\d]'), '');
    return clean.length == 10
        ? '${clean.substring(0, 5)}-${clean.substring(5)}'
        : mobile;
  }

  static bool isValidMobileNumber(String mobile) {
    final clean = mobile.replaceAll(RegExp(r'[^\d]'), '');
    return clean.length == 10 && clean[0] != '0';
  }
}

/// Response classes
class OtpResponse {
  final bool success;
  final String message;
  final String? sessionId;

  OtpResponse({
    required this.success,
    required this.message,
    this.sessionId,
  });
}

class AuthResponse {
  final bool success;
  final Map<String, dynamic>? user;
  final String message;

  AuthResponse({
    required this.success,
    this.user,
    required this.message,
  });
}

/// Custom exception
class MobileAuthException implements Exception {
  final String message;
  MobileAuthException(this.message);

  @override
  String toString() => 'MobileAuthException: $message';
}