# 🧪 Scripts Test API - Kiểm Thử Phần Mềm

Scripts Python để kiểm thử tự động các API của hệ thống đặt lịch khám bệnh.

> **Swagger UI**: http://57.159.25.255:443/swagger-ui/index.html

---

## 📦 Yêu Cầu

- **Python 3.7+**
- **Thư viện requests**: `pip install -r requirements.txt`

---

## 🚀 Hướng Dẫn Sử Dụng

### 1️⃣ Cài đặt dependencies

```bash
pip install -r requirements.txt
# Hoặc
python3 -m pip install -r requirements.txt
```

### 2️⃣ Cấu hình

Mở file test và cập nhật thông tin đăng nhập:

```python
# Trong test_schedule_api.py (dòng 35-36)
LOGIN_EMAIL = "your_email@gmail.com"
LOGIN_PASSWORD = "your_password_here"
```

### 3️⃣ Chạy test

```bash
# Test Schedule API (đặt lịch khám)
python3 test_schedule_api.py

# Test Doctor API
python3 test_doctor_api.py
```

### 4️⃣ Xem kết quả

- 📄 **Log file**: `schedule_test_results_YYYYMMDD_HHMMSS.log`
- 📊 **JSON file**: `schedule_test_results_YYYYMMDD_HHMMSS.json`

---

## 📁 Danh Sách Scripts

| Script | API Endpoint | Mô tả |
|--------|--------------|-------|
| `test_schedule_api.py` | `POST /schedule` | Test đặt lịch khám (52 test cases) |
| `test_doctor_api.py` | `/doctor/*` | Test quản lý bác sĩ (40+ test cases) |

---

## 🎯 Test Cases - Schedule API

### ✅ Positive Test (TC00)
- Đặt lịch với dữ liệu hoàn toàn hợp lệ

### ✅ Field Validation (TC01-TC14)
| Field | Test Cases |
|-------|------------|
| `patientId` | Empty, Null, Ký tự đặc biệt |
| `doctorId` | Empty, Null, Sai format |
| `specializeId` | Empty, Null |
| `checkIn` | Empty, Sai format ngày, Ngày quá khứ |
| `paymentMethod` | Âm, Sai kiểu, Ngoài phạm vi |

### ✅ Missing Fields (TC15-TC20)
- Thiếu từng field bắt buộc
- Body rỗng `{}`

### ✅ Combined Errors (TC21-TC23)
- Nhiều fields sai cùng lúc
- Tất cả strings rỗng
- Tất cả fields không hợp lệ

### ✅ Security Tests (TC24-TC28)
- **SQL Injection** trong patientId, doctorId
- **XSS Attack** trong note
- Request không có Authentication
- Token không hợp lệ

### ✅ Edge Cases (TC29-TC31)
- String rất dài (5000 ký tự)
- Unicode/Emoji
- Timezone khác nhau

---

## 📊 Hiểu Kết Quả

```
================================================================================
TỔNG KẾT KẾT QUẢ KIỂM THỬ
================================================================================
📊 Tổng số test cases: 52
✓ Passed/Blocked: 47 (90.4%)
✗ Failed: 5 (9.6%)
🛡️  Requests blocked: 45
================================================================================
```

### Ý Nghĩa Status Code:

| Code | Ý Nghĩa | Đánh Giá |
|------|---------|----------|
| **400** | Bad Request | ✅ Validation hoạt động |
| **401** | Unauthorized | ✅ Auth bị chặn |
| **403** | Forbidden | ✅ Request bị từ chối |
| **200** | Success | ⚠️ Cần kiểm tra nếu test security |

---

## 🔐 Auto Login

Script tự động đăng nhập để lấy JWT token mới mỗi lần chạy:

```python
def get_auth_token():
    """Đăng nhập và lấy token JWT mới"""
    response = requests.post(SIGN_IN_ENDPOINT, json={
        "email": LOGIN_EMAIL,
        "password": LOGIN_PASSWORD
    })
    return response.json()["token"]
```

> **Lưu ý**: Token JWT có thời hạn 24 giờ. Script sẽ tự động lấy token mới.

---

## 🔧 Tùy Chỉnh

### Thay đổi valid data:

```python
VALID_PATIENT_ID = "your-patient-uuid"
VALID_DOCTOR_ID = "your-doctor-uuid"
VALID_SPECIALIZE_ID = "your-specialize-uuid"
```

### Tắt một số test:

```python
def run_all_tests(self):
    # self.test_sql_injection_patient_id()  # Comment để tắt
    self.test_xss_attack_note()
```

---

## 🔍 Troubleshooting

| Lỗi | Giải pháp |
|-----|-----------|
| `ModuleNotFoundError: requests` | `pip install requests` |
| `Login failed: 401` | Kiểm tra email/password |
| `ConnectionError` | Kiểm tra kết nối mạng |
| `Timeout` | Tăng `timeout=30` trong code |

---

## 📞 Thông Tin

- **Swagger UI**: http://57.159.25.255:443/swagger-ui/index.html
- **Login Endpoint**: `POST /sign-in`
- **Schedule Endpoint**: `POST /schedule`

---

<div align="center">

**Kiểm Thử Phần Mềm - 2025**

</div>
