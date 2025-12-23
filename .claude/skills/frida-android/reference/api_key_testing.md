# Google/Firebase API Key Testing

When APKLeaks finds Google API keys (format: `AIzaSy...`), test their capabilities and restrictions.

## Quick Reference

| Service | Test Command | Enabled If |
|---------|--------------|------------|
| Maps Geocoding | `curl ".../geocode/json?address=test&key=KEY"` | Returns `results` array |
| Places | `curl ".../place/findplacefromtext/json?input=test&inputtype=textquery&key=KEY"` | Returns candidates |
| Directions | `curl ".../directions/json?origin=A&destination=B&key=KEY"` | Returns routes |
| YouTube | `curl ".../youtube/v3/search?part=snippet&q=test&key=KEY"` | Returns items |
| Translation | `curl ".../translate/v2?key=KEY&q=hello&target=es"` | Returns translations |
| Firebase Auth | POST to identitytoolkit | Returns tokens |
| Firebase RTDB | GET `PROJECT.firebaseio.com/.json` | Returns data or rules error |

---

## Google Maps APIs

### Geocoding API
```bash
curl "https://maps.googleapis.com/maps/api/geocode/json?address=Prague&key=API_KEY"
```
**Success:** Returns `results` array with location data
**Blocked:** Returns `REQUEST_DENIED` with error message

### Places API
```bash
curl "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=restaurant&inputtype=textquery&key=API_KEY"
```

### Directions API
```bash
curl "https://maps.googleapis.com/maps/api/directions/json?origin=Prague&destination=Vienna&key=API_KEY"
```

### Distance Matrix API
```bash
curl "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Prague&destinations=Vienna&key=API_KEY"
```

### Elevation API
```bash
curl "https://maps.googleapis.com/maps/api/elevation/json?locations=50.08,14.42&key=API_KEY"
```

### Static Maps (image)
```bash
curl "https://maps.googleapis.com/maps/api/staticmap?center=Prague&zoom=12&size=400x400&key=API_KEY" -o map.png
```

---

## YouTube Data API
```bash
curl "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=API_KEY&maxResults=1"
```
**Success:** Returns `items` array with video data

---

## Translation API
```bash
curl "https://translation.googleapis.com/language/translate/v2?key=API_KEY&q=hello&target=es"
```
**Success:** Returns `translations` with translated text

---

## Firebase Testing

### Firebase Auth - Anonymous Signup
```bash
curl "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```
**Success (anonymous enabled):** Returns `idToken`, `refreshToken`, `localId`
**Fail:** Returns `ADMIN_ONLY_OPERATION` or similar error

### Firebase Auth - Email/Password Signup
```bash
curl "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234","returnSecureToken":true}'
```

### Firebase Auth - Sign In
```bash
curl "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234","returnSecureToken":true}'
```

### Firebase Realtime Database - Public Read
```bash
# Find project name from apkleaks output (e.g., project-name.firebaseio.com)
curl "https://PROJECT-NAME.firebaseio.com/.json"
```
**Public access:** Returns database contents
**Restricted:** Returns `{"error":"Permission denied"}` or rules info

### Firebase Realtime Database - Specific Path
```bash
curl "https://PROJECT-NAME.firebaseio.com/users.json"
curl "https://PROJECT-NAME.firebaseio.com/config.json"
curl "https://PROJECT-NAME.firebaseio.com/admin.json"
```

### Firebase Storage - Public Read
```bash
# Find bucket from apkleaks (e.g., gs://project-name.appspot.com)
curl "https://firebasestorage.googleapis.com/v0/b/PROJECT-NAME.appspot.com/o"
```

---

## Billing/Abuse Potential Assessment

| Service | Abuse Potential | Notes |
|---------|-----------------|-------|
| Maps Geocoding | LOW | Free tier generous |
| Places API | MEDIUM | Costs per request |
| Directions | MEDIUM | Costs per request |
| YouTube Data | LOW | Read-only, quota limited |
| Translation | HIGH | Costs per character |
| Firebase Auth | LOW | Free tier generous |
| Firebase RTDB | VARIES | Depends on data sensitivity |
| Cloud Vision | HIGH | Costs per image |
| Cloud Speech | HIGH | Costs per audio minute |

---

## Key Restriction Detection

### Check if key has restrictions
```bash
# Try multiple APIs - restricted keys will only work for allowed APIs
# Also check for domain/IP restrictions by comparing responses from:
# 1. Direct curl
# 2. Curl with Referer header
curl -H "Referer: https://example.com" "https://maps.googleapis.com/..."
```

### Common restriction types:
1. **API restrictions** - Only specific APIs enabled
2. **HTTP referrer** - Only works from specific domains
3. **IP restrictions** - Only from specific IPs
4. **Android app** - Only from apps with specific SHA1/package
5. **iOS app** - Only from apps with specific bundle ID

---

## Report Template for Findings

```markdown
### Finding: Exposed Google API Key

**Key:** AIzaSy...XXXXX (redacted)
**Source:** APKLeaks static analysis

**Enabled APIs:**
- [ ] Maps Geocoding
- [ ] Places
- [ ] Directions
- [ ] YouTube Data
- [ ] Translation
- [ ] Firebase Auth
- [ ] Firebase RTDB

**Restrictions:**
- [ ] None detected (CRITICAL)
- [ ] API-restricted
- [ ] Referrer-restricted
- [ ] Android-app restricted

**Risk Level:** CRITICAL / HIGH / MEDIUM / LOW

**Recommendation:**
1. Add API restrictions in Google Cloud Console
2. Add application restrictions (Android SHA1 + package)
3. Rotate key if public exposure suspected
```

---

## Automation Script

```bash
#!/bin/bash
# api_key_test.sh - Quick test for Google API key capabilities

API_KEY="$1"

if [ -z "$API_KEY" ]; then
    echo "Usage: $0 <API_KEY>"
    exit 1
fi

echo "=== Testing API Key: $API_KEY ==="
echo ""

echo "[1] Maps Geocoding:"
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=$API_KEY" | jq -r '.status'

echo "[2] Places:"
curl -s "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=test&inputtype=textquery&key=$API_KEY" | jq -r '.status'

echo "[3] Directions:"
curl -s "https://maps.googleapis.com/maps/api/directions/json?origin=A&destination=B&key=$API_KEY" | jq -r '.status'

echo "[4] YouTube:"
curl -s "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=$API_KEY&maxResults=1" | jq -r 'if .error then .error.message else "OK" end'

echo "[5] Translation:"
curl -s "https://translation.googleapis.com/language/translate/v2?key=$API_KEY&q=test&target=es" | jq -r 'if .error then .error.message else "OK" end'

echo "[6] Firebase Auth (anon):"
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" -d '{}' | jq -r 'if .error then .error.message else "Anonymous signup enabled!" end'
```
