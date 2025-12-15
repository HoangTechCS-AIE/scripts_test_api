"""
Script test chức năng chặn request của API Schedule Controller
Kiểm thử phần mềm - Testing API Security & Validation

API endpoint được test:
- POST /schedule - Đặt lịch khám

Author: Student
Date: 2025-12-15
"""

import requests
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'schedule_test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Cấu hình API
BASE_URL = "http://57.159.25.255:443"
SCHEDULE_ENDPOINT = f"{BASE_URL}/schedule"
SIGN_IN_ENDPOINT = f"{BASE_URL}/sign-in"

# Thông tin đăng nhập (thay đổi theo tài khoản của bạn)
LOGIN_EMAIL = "linhleedev@gmail.com"
LOGIN_PASSWORD = "123456"  # ⚠️ Thay bằng password thực

# Token sẽ được lấy tự động khi chạy
AUTH_TOKEN = None


def get_auth_token() -> str:
    """Đăng nhập và lấy token JWT mới"""
    global AUTH_TOKEN
    
    logger.info("🔐 Đang đăng nhập để lấy token...")
    
    try:
        response = requests.post(
            SIGN_IN_ENDPOINT,
            json={
                "email": LOGIN_EMAIL,
                "password": LOGIN_PASSWORD
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            # Token có thể nằm trong các field khác nhau tùy API
            # Thử các field phổ biến
            token = data.get("token") or data.get("accessToken") or data.get("access_token") or data.get("data", {}).get("token")
            
            if token:
                AUTH_TOKEN = token
                logger.info(f"✓ Đăng nhập thành công! Token: {token[:50]}...")
                return token
            else:
                logger.error(f"✗ Không tìm thấy token trong response: {data}")
                raise Exception("Token not found in response")
        else:
            logger.error(f"✗ Đăng nhập thất bại! Status: {response.status_code}, Response: {response.text}")
            raise Exception(f"Login failed: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"✗ Lỗi kết nối khi đăng nhập: {str(e)}")
        raise


# Sample valid data (có thể điều chỉnh theo dữ liệu thực tế)
VALID_PATIENT_ID = "57777a46-5cb1-429a-88bf-05ea5d9ed871"
VALID_DOCTOR_ID = "c5d7576e-3922-43a9-97df-4fa6bfd77266"
VALID_SPECIALIZE_ID = "e9589ecd-3e19-415f-8481-63dabd247ae2"
VALID_CHECK_IN = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%dT10:00:00")
VALID_NOTE = "Khám định kỳ"
VALID_PAYMENT_METHOD = 0


class ScheduleAPITester:
    """Class để test API Schedule Controller"""
    
    def __init__(self):
        self.results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "blocked": 0,
            "details": []
        }
    
    def get_valid_payload(self) -> Dict[str, Any]:
        """Trả về payload hợp lệ làm baseline"""
        return {
            "patientId": VALID_PATIENT_ID,
            "doctorId": VALID_DOCTOR_ID,
            "specializeId": VALID_SPECIALIZE_ID,
            "checkIn": VALID_CHECK_IN,
            "note": VALID_NOTE,
            "paymentMethod": VALID_PAYMENT_METHOD
        }
    
    def log_test_result(self, test_name: str, expected_status: int, 
                       actual_status: int, response_data: Any, 
                       test_type: str = "BLOCK"):
        """Ghi lại kết quả test"""
        self.results["total_tests"] += 1
        
        if test_type == "BLOCK":
            # Test mong đợi request bị chặn (4xx, 5xx)
            if actual_status >= 400:
                status = "✓ BLOCKED"
                self.results["blocked"] += 1
                self.results["passed"] += 1
            else:
                status = "✗ NOT BLOCKED"
                self.results["failed"] += 1
        else:
            # Test mong đợi request thành công
            if actual_status == expected_status:
                status = "✓ PASSED"
                self.results["passed"] += 1
            else:
                status = "✗ FAILED"
                self.results["failed"] += 1
        
        result = {
            "test": test_name,
            "expected_status": expected_status,
            "actual_status": actual_status,
            "status": status,
            "response": str(response_data)[:500]  # Giới hạn độ dài response
        }
        
        self.results["details"].append(result)
        
        logger.info(f"{status} | {test_name} | Expected: {expected_status} | Got: {actual_status}")
        if actual_status >= 400:
            logger.info(f"  Response: {str(response_data)[:200]}")
    
    def send_request(self, payload: Dict[str, Any], headers: Optional[Dict] = None, 
                     include_auth: bool = True) -> tuple:
        """Gửi request đến API và trả về (status_code, response_text)
        
        Args:
            payload: Request body
            headers: Custom headers (sẽ được merge với auth header)
            include_auth: Có thêm auth token hay không (default: True)
        """
        try:
            request_headers = {}
            
            # Thêm auth token nếu cần
            if include_auth:
                request_headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
            
            # Merge với custom headers nếu có
            if headers:
                request_headers.update(headers)
            
            response = requests.post(
                SCHEDULE_ENDPOINT,
                json=payload,
                headers=request_headers if request_headers else None,
                timeout=10
            )
            return response.status_code, response.text
        except requests.exceptions.Timeout:
            return 408, "Request Timeout"
        except requests.exceptions.RequestException as e:
            return 0, str(e)

    # ========== 0. TEST CASE HỢP LỆ (POSITIVE TEST) ==========
    
    def test_valid_schedule_request(self):
        """TC00: Test đặt lịch với dữ liệu hoàn toàn hợp lệ"""
        logger.info("\n=== TC00: Đặt lịch hợp lệ (POSITIVE TEST) ===")
        payload = self.get_valid_payload()
        
        status, response = self.send_request(payload)
        
        # Mong đợi 200 OK hoặc 201 Created
        if status in [200, 201]:
            self.log_test_result("TC00: Đặt lịch hợp lệ", 200, status, response, test_type="PASS")
        else:
            # Log chi tiết nếu không thành công
            logger.warning(f"  ⚠️ Request hợp lệ nhưng không thành công: {response}")
            self.log_test_result("TC00: Đặt lịch hợp lệ", 200, status, response, test_type="PASS")

    # ========== 1. TEST TỪNG FIELD RIÊNG LẺ ==========
    
    def test_patient_id_empty(self):
        """TC01: Test patientId rỗng"""
        logger.info("\n=== TC01: patientId rỗng ===")
        payload = self.get_valid_payload()
        payload["patientId"] = ""
        
        status, response = self.send_request(payload)
        self.log_test_result("TC01: patientId rỗng", 400, status, response)
    
    def test_patient_id_null(self):
        """TC02: Test patientId null"""
        logger.info("\n=== TC02: patientId null ===")
        payload = self.get_valid_payload()
        payload["patientId"] = None
        
        status, response = self.send_request(payload)
        self.log_test_result("TC02: patientId null", 400, status, response)
    
    def test_patient_id_special_chars(self):
        """TC03: Test patientId chứa ký tự đặc biệt"""
        logger.info("\n=== TC03: patientId ký tự đặc biệt ===")
        payload = self.get_valid_payload()
        payload["patientId"] = "!@#$%^&*()"
        
        status, response = self.send_request(payload)
        self.log_test_result("TC03: patientId ký tự đặc biệt", 400, status, response)
    
    def test_doctor_id_empty(self):
        """TC04: Test doctorId rỗng"""
        logger.info("\n=== TC04: doctorId rỗng ===")
        payload = self.get_valid_payload()
        payload["doctorId"] = ""
        
        status, response = self.send_request(payload)
        self.log_test_result("TC04: doctorId rỗng", 400, status, response)
    
    def test_doctor_id_null(self):
        """TC05: Test doctorId null"""
        logger.info("\n=== TC05: doctorId null ===")
        payload = self.get_valid_payload()
        payload["doctorId"] = None
        
        status, response = self.send_request(payload)
        self.log_test_result("TC05: doctorId null", 400, status, response)
    
    def test_doctor_id_invalid_format(self):
        """TC06: Test doctorId sai format"""
        logger.info("\n=== TC06: doctorId sai format ===")
        payload = self.get_valid_payload()
        payload["doctorId"] = "invalid-format-123!@#"
        
        status, response = self.send_request(payload)
        self.log_test_result("TC06: doctorId sai format", 400, status, response)
    
    def test_specialize_id_empty(self):
        """TC07: Test specializeId rỗng"""
        logger.info("\n=== TC07: specializeId rỗng ===")
        payload = self.get_valid_payload()
        payload["specializeId"] = ""
        
        status, response = self.send_request(payload)
        self.log_test_result("TC07: specializeId rỗng", 400, status, response)
    
    def test_specialize_id_null(self):
        """TC08: Test specializeId null"""
        logger.info("\n=== TC08: specializeId null ===")
        payload = self.get_valid_payload()
        payload["specializeId"] = None
        
        status, response = self.send_request(payload)
        self.log_test_result("TC08: specializeId null", 400, status, response)
    
    def test_check_in_empty(self):
        """TC09: Test checkIn rỗng"""
        logger.info("\n=== TC09: checkIn rỗng ===")
        payload = self.get_valid_payload()
        payload["checkIn"] = ""
        
        status, response = self.send_request(payload)
        self.log_test_result("TC09: checkIn rỗng", 400, status, response)
    
    def test_check_in_invalid_format(self):
        """TC10: Test checkIn sai format ngày"""
        logger.info("\n=== TC10: checkIn sai format ===")
        test_cases = [
            ("31-12-2025", "DD-MM-YYYY format"),
            ("2025/12/31", "Slash separator"),
            ("abc123", "Random string"),
            ("2025-13-01", "Invalid month"),
            ("2025-12-32", "Invalid day"),
        ]
        
        for invalid_date, description in test_cases:
            payload = self.get_valid_payload()
            payload["checkIn"] = invalid_date
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC10: checkIn {description}", 400, status, response)
    
    def test_check_in_past_date(self):
        """TC11: Test checkIn ngày trong quá khứ"""
        logger.info("\n=== TC11: checkIn ngày quá khứ ===")
        payload = self.get_valid_payload()
        past_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT10:00:00")
        payload["checkIn"] = past_date
        
        status, response = self.send_request(payload)
        self.log_test_result("TC11: checkIn ngày quá khứ", 400, status, response)
    
    def test_payment_method_negative(self):
        """TC12: Test paymentMethod âm"""
        logger.info("\n=== TC12: paymentMethod âm ===")
        payload = self.get_valid_payload()
        payload["paymentMethod"] = -1
        
        status, response = self.send_request(payload)
        self.log_test_result("TC12: paymentMethod âm", 400, status, response)
    
    def test_payment_method_invalid_type(self):
        """TC13: Test paymentMethod sai kiểu"""
        logger.info("\n=== TC13: paymentMethod sai kiểu ===")
        test_cases = [
            ("abc", "String value"),
            (1.5, "Float value"),
            (True, "Boolean value"),
        ]
        
        for invalid_value, description in test_cases:
            payload = self.get_valid_payload()
            payload["paymentMethod"] = invalid_value
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC13: paymentMethod {description}", 400, status, response)
    
    def test_payment_method_out_of_range(self):
        """TC14: Test paymentMethod ngoài phạm vi"""
        logger.info("\n=== TC14: paymentMethod ngoài phạm vi ===")
        test_cases = [100, 999, 9999999]
        
        for invalid_value in test_cases:
            payload = self.get_valid_payload()
            payload["paymentMethod"] = invalid_value
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC14: paymentMethod = {invalid_value}", 400, status, response)

    # ========== 2. TEST THIẾU FIELD BẮT BUỘC ==========
    
    def test_missing_patient_id(self):
        """TC15: Thiếu patientId"""
        logger.info("\n=== TC15: Thiếu patientId ===")
        payload = self.get_valid_payload()
        del payload["patientId"]
        
        status, response = self.send_request(payload)
        self.log_test_result("TC15: Thiếu patientId", 400, status, response)
    
    def test_missing_doctor_id(self):
        """TC16: Thiếu doctorId"""
        logger.info("\n=== TC16: Thiếu doctorId ===")
        payload = self.get_valid_payload()
        del payload["doctorId"]
        
        status, response = self.send_request(payload)
        self.log_test_result("TC16: Thiếu doctorId", 400, status, response)
    
    def test_missing_specialize_id(self):
        """TC17: Thiếu specializeId"""
        logger.info("\n=== TC17: Thiếu specializeId ===")
        payload = self.get_valid_payload()
        del payload["specializeId"]
        
        status, response = self.send_request(payload)
        self.log_test_result("TC17: Thiếu specializeId", 400, status, response)
    
    def test_missing_check_in(self):
        """TC18: Thiếu checkIn"""
        logger.info("\n=== TC18: Thiếu checkIn ===")
        payload = self.get_valid_payload()
        del payload["checkIn"]
        
        status, response = self.send_request(payload)
        self.log_test_result("TC18: Thiếu checkIn", 400, status, response)
    
    def test_missing_payment_method(self):
        """TC19: Thiếu paymentMethod"""
        logger.info("\n=== TC19: Thiếu paymentMethod ===")
        payload = self.get_valid_payload()
        del payload["paymentMethod"]
        
        status, response = self.send_request(payload)
        self.log_test_result("TC19: Thiếu paymentMethod", 400, status, response)
    
    def test_empty_body(self):
        """TC20: Body rỗng"""
        logger.info("\n=== TC20: Body rỗng ===")
        status, response = self.send_request({})
        self.log_test_result("TC20: Body rỗng", 400, status, response)

    # ========== 3. TEST TỔNG HỢP ==========
    
    def test_multiple_invalid_fields(self):
        """TC21: Nhiều field sai cùng lúc"""
        logger.info("\n=== TC21: patientId + doctorId đều sai ===")
        payload = self.get_valid_payload()
        payload["patientId"] = ""
        payload["doctorId"] = None
        
        status, response = self.send_request(payload)
        self.log_test_result("TC21: patientId + doctorId sai", 400, status, response)
    
    def test_all_strings_empty(self):
        """TC22: Tất cả string fields đều rỗng"""
        logger.info("\n=== TC22: Tất cả string rỗng ===")
        payload = {
            "patientId": "",
            "doctorId": "",
            "specializeId": "",
            "checkIn": "",
            "note": "",
            "paymentMethod": 0
        }
        
        status, response = self.send_request(payload)
        self.log_test_result("TC22: Tất cả string rỗng", 400, status, response)
    
    def test_all_fields_invalid(self):
        """TC23: Tất cả fields có giá trị không hợp lệ"""
        logger.info("\n=== TC23: Tất cả fields không hợp lệ ===")
        payload = {
            "patientId": None,
            "doctorId": None,
            "specializeId": None,
            "checkIn": "invalid-date",
            "note": None,
            "paymentMethod": -999
        }
        
        status, response = self.send_request(payload)
        self.log_test_result("TC23: Tất cả fields không hợp lệ", 400, status, response)

    # ========== 4. TEST SECURITY ==========
    
    def test_sql_injection_patient_id(self):
        """TC24: SQL Injection trong patientId"""
        logger.info("\n=== TC24: SQL Injection - patientId ===")
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE schedules; --",
            "1' UNION SELECT NULL--",
            "admin'--",
            "1; DELETE FROM users WHERE '1'='1",
        ]
        
        for sql_payload in sql_payloads:
            payload = self.get_valid_payload()
            payload["patientId"] = sql_payload
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC24: SQLi patientId: {sql_payload[:25]}...", 400, status, response)
    
    def test_sql_injection_doctor_id(self):
        """TC25: SQL Injection trong doctorId"""
        logger.info("\n=== TC25: SQL Injection - doctorId ===")
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE doctors; --",
            "1' UNION SELECT * FROM users--",
        ]
        
        for sql_payload in sql_payloads:
            payload = self.get_valid_payload()
            payload["doctorId"] = sql_payload
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC25: SQLi doctorId: {sql_payload[:25]}...", 400, status, response)
    
    def test_xss_attack_note(self):
        """TC26: XSS Attack trong note"""
        logger.info("\n=== TC26: XSS Attack - note ===")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><img src=x onerror=alert(1)>",
        ]
        
        for xss_payload in xss_payloads:
            payload = self.get_valid_payload()
            payload["note"] = xss_payload
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC26: XSS note: {xss_payload[:25]}...", 400, status, response)
    
    def test_no_authentication(self):
        """TC27: Request không có Authentication"""
        logger.info("\n=== TC27: Không có Authentication ===")
        payload = self.get_valid_payload()
        
        # Gửi request KHÔNG có token
        status, response = self.send_request(payload, include_auth=False)
        self.log_test_result("TC27: Không có Auth Token", 401, status, response)
    
    def test_invalid_token(self):
        """TC28: Request với Token không hợp lệ"""
        logger.info("\n=== TC28: Token không hợp lệ ===")
        payload = self.get_valid_payload()
        
        # Gửi request với token sai (override auth header)
        headers = {"Authorization": "Bearer invalid_token_12345"}
        status, response = self.send_request(payload, headers=headers, include_auth=False)
        self.log_test_result("TC28: Token không hợp lệ", 401, status, response)

    # ========== 5. TEST EDGE CASES ==========
    
    def test_very_long_string(self):
        """TC29: String rất dài (>1000 ký tự)"""
        logger.info("\n=== TC29: String rất dài ===")
        payload = self.get_valid_payload()
        payload["note"] = "A" * 5000  # 5000 ký tự
        
        status, response = self.send_request(payload)
        self.log_test_result("TC29: note 5000 ký tự", 400, status, response)
    
    def test_unicode_emoji_note(self):
        """TC30: Unicode/Emoji trong note"""
        logger.info("\n=== TC30: Unicode/Emoji ===")
        payload = self.get_valid_payload()
        payload["note"] = "Đặt lịch khám 🏥 Bác sĩ 👨‍⚕️ Đau bụng 💊 测试中文 العربية"
        
        status, response = self.send_request(payload)
        # Note với Unicode/Emoji có thể hợp lệ, kiểm tra không crash
        self.log_test_result("TC30: Unicode/Emoji note", 200, status, response, test_type="PASS")
    
    def test_check_in_different_timezone(self):
        """TC31: checkIn với timezone khác"""
        logger.info("\n=== TC31: checkIn timezone khác ===")
        test_cases = [
            "2025-12-20T10:00:00Z",  # UTC
            "2025-12-20T10:00:00+07:00",  # Vietnam
            "2025-12-20T10:00:00-05:00",  # US Eastern
        ]
        
        for tz_time in test_cases:
            payload = self.get_valid_payload()
            payload["checkIn"] = tz_time
            
            status, response = self.send_request(payload)
            self.log_test_result(f"TC31: checkIn {tz_time}", 200, status, response, test_type="PASS")

    # ========== RUN ALL TESTS ==========
    
    def run_all_tests(self):
        """Chạy tất cả các test cases"""
        logger.info("=" * 80)
        logger.info("BẮT ĐẦU KIỂM THỬ API SCHEDULE CONTROLLER")
        logger.info(f"Endpoint: {SCHEDULE_ENDPOINT}")
        logger.info("=" * 80)
        
        # 0. Test case hợp lệ (Positive test)
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 0: POSITIVE TEST - DỮ LIỆU HỢP LỆ")
        logger.info("=" * 40)
        self.test_valid_schedule_request()
        
        # 1. Test từng field riêng lẻ
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 1: TEST TỪNG FIELD RIÊNG LẺ")
        logger.info("=" * 40)
        self.test_patient_id_empty()
        self.test_patient_id_null()
        self.test_patient_id_special_chars()
        self.test_doctor_id_empty()
        self.test_doctor_id_null()
        self.test_doctor_id_invalid_format()
        self.test_specialize_id_empty()
        self.test_specialize_id_null()
        self.test_check_in_empty()
        self.test_check_in_invalid_format()
        self.test_check_in_past_date()
        self.test_payment_method_negative()
        self.test_payment_method_invalid_type()
        self.test_payment_method_out_of_range()
        
        # 2. Test thiếu field bắt buộc
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 2: TEST THIẾU FIELD BẮT BUỘC")
        logger.info("=" * 40)
        self.test_missing_patient_id()
        self.test_missing_doctor_id()
        self.test_missing_specialize_id()
        self.test_missing_check_in()
        self.test_missing_payment_method()
        self.test_empty_body()
        
        # 3. Test tổng hợp
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 3: TEST TỔNG HỢP")
        logger.info("=" * 40)
        self.test_multiple_invalid_fields()
        self.test_all_strings_empty()
        self.test_all_fields_invalid()
        
        # 4. Test security
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 4: TEST SECURITY")
        logger.info("=" * 40)
        self.test_sql_injection_patient_id()
        self.test_sql_injection_doctor_id()
        self.test_xss_attack_note()
        self.test_no_authentication()
        self.test_invalid_token()
        
        # 5. Test edge cases
        logger.info("\n" + "=" * 40)
        logger.info("PHẦN 5: TEST EDGE CASES")
        logger.info("=" * 40)
        self.test_very_long_string()
        self.test_unicode_emoji_note()
        self.test_check_in_different_timezone()
        
        # In báo cáo tổng kết
        self.print_summary()
    
    def print_summary(self):
        """In báo cáo tổng kết"""
        logger.info("\n" + "=" * 80)
        logger.info("TỔNG KẾT KẾT QUẢ KIỂM THỬ")
        logger.info("=" * 80)
        
        total = self.results['total_tests']
        if total > 0:
            passed_pct = self.results['passed'] / total * 100
            failed_pct = self.results['failed'] / total * 100
        else:
            passed_pct = failed_pct = 0
        
        logger.info(f"📊 Tổng số test cases: {total}")
        logger.info(f"✓ Passed/Blocked: {self.results['passed']} ({passed_pct:.1f}%)")
        logger.info(f"✗ Failed: {self.results['failed']} ({failed_pct:.1f}%)")
        logger.info(f"🛡️  Requests blocked: {self.results['blocked']}")
        logger.info("=" * 80)
        
        # Lưu kết quả chi tiết vào file JSON
        output_file = f"schedule_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n📄 Chi tiết kết quả đã được lưu vào: {output_file}")
        
        # Phân tích các test failed
        if self.results['failed'] > 0:
            logger.info("\n⚠️  CÁC TEST CASE KHÔNG BỊ CHẶN (CẦN XEM XÉT):")
            for detail in self.results['details']:
                if "NOT BLOCKED" in detail['status'] or "FAILED" in detail['status']:
                    logger.info(f"  - {detail['test']}: Status {detail['actual_status']}")


def main():
    """Hàm main để chạy test"""
    # Bước 1: Đăng nhập và lấy token
    try:
        get_auth_token()
    except Exception as e:
        logger.error(f"Không thể đăng nhập! Dừng test. Error: {e}")
        return
    
    # Bước 2: Chạy tất cả test cases
    tester = ScheduleAPITester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
