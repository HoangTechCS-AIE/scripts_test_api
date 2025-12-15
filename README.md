# 🧪 Script Test API Doctor Controller

Script Python để kiểm thử chức năng chặn request của các API trong **doctor-controller**.

> **Swagger UI**: http://57.159.25.255:443/swagger-ui/index.html#/doctor-controller

---

## 📦 Yêu Cầu Hệ Thống

- **Python 3.7+** (chưa cài? xem [Hướng dẫn cài đặt Python](#-cài-đặt-python))
- **Kết nối Internet** để gọi API
- **Thư viện requests** (cài tự động qua requirements.txt)

---

## 🚀 Hướng Dẫn Sử Dụng Nhanh

### 1️⃣ Cài đặt dependencies

```bash
# Trên Windows
python -m pip install -r requirements.txt

# Hoặc nếu bạn có py launcher
py -m pip install -r requirements.txt
```

### 2️⃣ Chạy script test

```bash
# Trên Windows
python test_doctor_api.py

# Hoặc
py test_doctor_api.py
```

### 3️⃣ Xem kết quả

Sau khi chạy xong, bạn sẽ có:
- 📄 **File log**: `api_test_results_YYYYMMDD_HHMMSS.log`
- 📊 **File JSON**: `test_results_YYYYMMDD_HHMMSS.json`

---

## 🎯 Các API Được Test

Script kiểm thử **4 API endpoints** trong doctor-controller:

| Method | Endpoint | Chức năng |
|--------|----------|-----------|
| `POST` | `/doctor` | Thêm bác sĩ mới |
| `PUT` | `/doctor` | Cập nhật thông tin bác sĩ |
| `PUT` | `/doctor/day` | Đặt số người khám tối đa theo ngày |
| `DELETE` | `/doctor/{ids}` | Xóa bác sĩ theo ID |

---

## 🧪 Test Cases (40+ scenarios)

### ✅ Authentication Tests
- Request không có token (401 Unauthorized)
- Request với token không hợp lệ (401 Unauthorized)
- Request với user không có quyền (403 Forbidden)

### ✅ Validation Tests
- Thiếu trường bắt buộc (400 Bad Request)
- Giá trị không hợp lệ: ID âm, ID = 0, ID quá lớn
- Kiểu dữ liệu sai: string thay vì number
- Giá trị vô lý: maxPatients = 0 hoặc 1000

### ✅ Security Tests

**SQL Injection:**
```sql
' OR '1'='1
'; DROP TABLE doctors; --
1' UNION SELECT NULL--
admin'--
```

**XSS (Cross-Site Scripting):**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

### ✅ Rate Limiting
- Gửi 20 requests liên tiếp (kiểm tra 429 Too Many Requests)

---

## 📊 Hiểu Kết Quả Test

### Console Output Mẫu:

```
================================================================================
BẮT ĐẦU KIỂM THỬ API DOCTOR CONTROLLER
================================================================================

=== Testing POST /doctor - No Authentication ===
✓ BLOCKED | POST /doctor - No Auth Token | Expected: 401 | Got: 401
  Response: {"error":"Unauthorized"}

=== Testing POST /doctor - SQL Injection ===
✓ BLOCKED | POST /doctor - SQL Injection: ' OR '1'='1 | Expected: 400 | Got: 400

================================================================================
TỔNG KẾT KẾT QUẢ KIỂM THỬ
================================================================================
Tổng số test cases: 35
✓ Passed/Blocked: 32 (91.4%)
✗ Failed: 3 (8.6%)
🛡️  Requests blocked: 32
================================================================================

📄 Chi tiết kết quả đã được lưu vào: test_results_20251215_191234.json
```

### Ý Nghĩa Status Code:

| Code | Ý Nghĩa | Đánh Giá |
|------|---------|----------|
| **401** | Unauthorized - Không có quyền | ✅ TỐT - Request bị chặn |
| **403** | Forbidden - Không đủ quyền | ✅ TỐT - Request bị chặn |
| **400** | Bad Request - Dữ liệu không hợp lệ | ✅ TỐT - Validation hoạt động |
| **429** | Too Many Requests | ✅ TỐT - Rate limiting hoạt động |
| **200** | Success | ⚠️ CHÚ Ý - Cần kiểm tra nếu test security |
| **500** | Server Error | ❌ XẤU - Lỗi server |

---

## 🔧 Tùy Chỉnh Script

### Thay đổi URL:

Mở `test_doctor_api.py`, tìm và sửa:

```python
BASE_URL = "http://57.159.25.255:443"
```

### Thêm authentication token:

Nếu bạn có token hợp lệ:

```python
headers = {
    "Authorization": "Bearer YOUR_TOKEN_HERE"
}
response = requests.post(
    DOCTOR_ENDPOINT,
    headers=headers,
    json={"name": "Dr. Test"},
    timeout=10
)
```

### Tắt một số test cases:

Comment các dòng trong hàm `run_all_tests()`:

```python
def run_all_tests(self):
    # self.test_post_doctor_no_auth()  # Tắt test này
    self.test_post_doctor_invalid_token()
    # ... các test khác
```

---

## 🐍 Cài Đặt Python

### Windows:

#### Cách 1: Tải từ python.org
1. Truy cập: https://www.python.org/downloads/
2. Tải **Python 3.12** (hoặc mới hơn)
3. Chạy installer
4. ✅ **QUAN TRỌNG**: Tick ☑️ "Add Python to PATH"
5. Click "Install Now"

#### Cách 2: Microsoft Store
1. Mở **Microsoft Store**
2. Tìm "Python 3.12"
3. Click "Get" để cài đặt

### Kiểm tra cài đặt:

```bash
python --version
# Hoặc
py --version
```

Kết quả mong đợi:
```
Python 3.12.x
```

---

## 📁 Cấu Trúc Thư Mục

```
KTPM/
├── test_doctor_api.py          # Script test chính
├── requirements.txt             # Dependencies
├── README.md                    # File này
├── api_test_results_*.log      # Log files (tự động tạo)
└── test_results_*.json         # JSON results (tự động tạo)
```

---

## 🔍 Troubleshooting

### ❌ Lỗi: `pip: command not found`

**Nguyên nhân**: Python chưa được thêm vào PATH

**Giải pháp**:
```bash
# Thử các lệnh sau:
python -m pip install -r requirements.txt
py -m pip install -r requirements.txt
python3 -m pip install -r requirements.txt
```

### ❌ Lỗi: `ModuleNotFoundError: No module named 'requests'`

**Giải pháp**:
```bash
python -m pip install requests
```

### ❌ Lỗi: `ConnectionError`

**Nguyên nhân**: Không kết nối được đến server

**Giải pháp**:
1. Kiểm tra kết nối Internet
2. Kiểm tra URL có đúng không
3. Thử ping server: `ping 57.159.25.255`
4. Kiểm tra firewall/proxy

### ❌ Lỗi: `Timeout`

**Giải pháp**: Tăng timeout trong script (đổi `timeout=10` thành `timeout=30`)

### ❌ Lỗi: `Python was not found`

**Giải pháp**: Cài đặt Python theo hướng dẫn [ở đây](#-cài-đặt-python)

---

## 📝 Ví Dụ Sử Dụng

### Chạy test đầy đủ:

```bash
cd c:\Users\LENOVO\Desktop\KTPM
python test_doctor_api.py
```

### Chỉ xem log:

```bash
# Xem log mới nhất
type api_test_results_*.log | more
```

### Phân tích JSON:

```python
import json

# Đọc file JSON
with open('test_results_20251215_191234.json', 'r', encoding='utf-8') as f:
    results = json.load(f)

print(f"Tổng tests: {results['total_tests']}")
print(f"Passed: {results['passed']}")
print(f"Failed: {results['failed']}")
```

---

## 💡 Tips

1. **Chạy test nhiều lần** - Đảm bảo kết quả nhất quán
2. **So sánh log files** - Xem sự thay đổi qua các lần chạy
3. **Báo cáo bugs** - Nếu phát hiện lỗ hổng bảo mật
4. **Backup kết quả** - Lưu log files để tham khảo sau
5. **Update test cases** - Khi API có thay đổi

---

## 📞 Hỗ Trợ

### Các file liên quan:

- [`test_doctor_api.py`](test_doctor_api.py) - Script test chính
- [`requirements.txt`](requirements.txt) - Dependencies
- [Swagger UI](http://57.159.25.255:443/swagger-ui/index.html#/doctor-controller) - API Documentation

### Thông tin test:

- **Tổng test cases**: 40+
- **API endpoints**: 4
- **Test categories**: Authentication, Validation, Security, Rate Limiting
- **Thời gian chạy**: ~30-60 giây

---

## ✅ Checklist Trước Khi Chạy

- [ ] Python đã được cài đặt (version 3.7+)
- [ ] Dependencies đã được cài (`pip install -r requirements.txt`)
- [ ] Kết nối Internet hoạt động
- [ ] URL API đúng và có thể truy cập
- [ ] Đã đọc hiểu các test cases

---

## 🎉 Kết Luận

Script này giúp bạn:

✅ Kiểm thử toàn diện 4 API endpoints  
✅ Test 40+ scenarios khác nhau  
✅ Phát hiện lỗ hổng bảo mật (SQL Injection, XSS)  
✅ Kiểm tra authentication & authorization  
✅ Tự động log và báo cáo kết quả  
✅ Dễ dàng mở rộng thêm test cases  

**Chúc bạn kiểm thử thành công!** 🚀

---

<div align="center">

**Made for Software Testing Practice**  
*Kiểm Thử Phần Mềm - 2025*

</div>
