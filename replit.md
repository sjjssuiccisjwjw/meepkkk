# UNITED HUB - MeepCity Scripts Platform

## Overview

UNITED HUB is a Flask-based web application that provides access to premium MeepCity (Roblox) scripts through a key-based authentication system. The platform features an admin panel for key management, user verification system, and Discord webhook integrations for monitoring and notifications.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Database**: SQLAlchemy ORM with configurable database backend (DATABASE_URL environment variable)
- **Session Management**: Flask sessions with configurable secret key
- **Proxy Support**: ProxyFix middleware for handling reverse proxy headers

### Frontend Architecture
- **Template Engine**: Jinja2 (Flask's default)
- **CSS Framework**: Bootstrap 5.3.0
- **Icons**: Feather Icons
- **JavaScript**: Vanilla JavaScript with Bootstrap components

### Authentication System
- **Key-based Access**: Users must verify private keys to access premium scripts
- **Session Persistence**: Verified keys are stored in Flask sessions
- **Admin Access**: Special admin key ('SEMNEXO134') provides administrative privileges

## Key Components

### Database Models
1. **PrivateKey Model**
   - Manages access keys with expiration and usage limits
   - Tracks creation, usage count, and validity status
   - Supports key descriptions and creator attribution

2. **AccessLog Model**
   - Records all access attempts with detailed metadata
   - Captures IP addresses, user agents, device info, and location data
   - Tracks script access and key usage for analytics

### Core Routes
- **Index Route** (`/`): Landing page with key verification access
- **Verification Route** (`/verify`): Key validation and session management
- **Scripts Route** (`/scripts`): Protected script library access
- **Admin Panel** (`/admin`): Administrative interface for key and log management

### External Integrations
- **Discord Webhooks**: Multiple webhook endpoints for different notification types:
  - General chat notifications
  - Key generator notifications
  - DM notifications
  - Verification success/error notifications

## Data Flow

1. **User Access**: Users visit the platform and must verify a private key
2. **Key Verification**: System validates key against database and checks expiration/usage limits
3. **Session Creation**: Valid keys create persistent sessions for script access
4. **Script Access**: Verified users can browse and access categorized scripts
5. **Logging**: All access attempts are logged with detailed metadata
6. **Discord Notifications**: Various events trigger Discord webhook notifications

## External Dependencies

### Required Python Packages
- Flask and Flask-SQLAlchemy for web framework and ORM
- Requests for HTTP operations (Discord webhooks)
- User-agents for device detection
- Werkzeug for proxy handling

### Third-party Services
- **Discord Webhooks**: Real-time notifications and monitoring
- **Database Service**: Configurable via DATABASE_URL environment variable

### Frontend Dependencies
- Bootstrap 5.3.0 (CDN)
- Feather Icons (CDN)

## Deployment Strategy

### Environment Configuration
- **SESSION_SECRET**: Flask session encryption key
- **DATABASE_URL**: Database connection string
- **DISCORD_WEBHOOK_URL**: Primary Discord notification endpoint
- **API_SECRET_KEY**: API authentication (referenced but not fully implemented)

### Database Setup
- Uses SQLAlchemy with automatic table creation
- Connection pooling with health checks (pool_recycle, pool_pre_ping)
- Configurable database backend support

### Scaling Considerations
- Stateless design with database-backed sessions
- Proxy-aware configuration for load balancer compatibility
- Webhook-based notifications reduce server-side notification complexity

### Security Features
- Key-based authentication system
- Session management with secure secret keys
- Access logging for security monitoring
- Input validation and sanitization