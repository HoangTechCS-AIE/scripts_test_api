"""
Script test chức năng chặn request của các API trong Doctor Controller
Kiểm thử phần mềm - Testing API Security & Validation

API endpoints được test:
1. POST /doctor - Thêm bác sĩ
2. PUT /doctor - Cập nhật bác sĩ  
3. PUT /doctor/day - Đặt số người khám tối đa
4. DELETE /doctor/{ids} - Xóa bác sĩ

Author: Student
Date: 2025-12-15
"""

import requests
import json
import logging
from datetime import datetime
from typing import Dict, Any, List

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'api_test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Cấu hình API
BASE_URL = "http://57.159.25.255:443"
DOCTOR_ENDPOINT = f"{BASE_URL}/doctor"
DOCTOR_DAY_ENDPOINT = f"{BASE_URL}/doctor/day"


class DoctorAPITester:
    """Class để test các API của Doctor Controller"""
    
    def __init__(self):
        self.results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "blocked": 0,
            "details": []
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
            "response": str(response_data)[:200]  # Giới hạn độ dài response
        }
        
        self.results["details"].append(result)
        
        logger.info(f"{status} | {test_name} | Expected: {expected_status} | Got: {actual_status}")
        if actual_status >= 400:
            logger.info(f"  Response: {response_data}")
    
    def test_post_doctor_no_auth(self):
        """Test POST /doctor không có authentication"""
        logger.info("\n=== Testing POST /doctor - No Authentication ===")
        
        try:
            response = requests.post(
                DOCTOR_ENDPOINT,
                json={
                    "name": "Dr. Test",
                    "specialty": "Cardiology"
                },
                timeout=10
            )
            
            self.log_test_result(
                "POST /doctor - No Auth Token",
                expected_status=401,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_post_doctor_no_auth: {str(e)}")
    
    def test_post_doctor_invalid_token(self):
        """Test POST /doctor với token không hợp lệ"""
        logger.info("\n=== Testing POST /doctor - Invalid Token ===")
        
        try:
            headers = {
                "Authorization": "Bearer invalid_token_12345"
            }
            response = requests.post(
                DOCTOR_ENDPOINT,
                headers=headers,
                json={
                    "name": "Dr. Test",
                    "specialty": "Cardiology"
                },
                timeout=10
            )
            
            self.log_test_result(
                "POST /doctor - Invalid Token",
                expected_status=401,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_post_doctor_invalid_token: {str(e)}")
    
    def test_post_doctor_missing_fields(self):
        """Test POST /doctor thiếu trường bắt buộc"""
        logger.info("\n=== Testing POST /doctor - Missing Required Fields ===")
        
        test_cases = [
            ({}, "Empty body"),
            ({"name": ""}, "Empty name"),
            ({"specialty": "Cardiology"}, "Missing name"),
        ]
        
        for payload, description in test_cases:
            try:
                response = requests.post(
                    DOCTOR_ENDPOINT,
                    json=payload,
                    timeout=10
                )
                
                self.log_test_result(
                    f"POST /doctor - {description}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing {description}: {str(e)}")
    
    def test_post_doctor_sql_injection(self):
        """Test POST /doctor với SQL injection attempts"""
        logger.info("\n=== Testing POST /doctor - SQL Injection ===")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE doctors; --",
            "1' UNION SELECT NULL--",
            "admin'--",
        ]
        
        for payload in sql_payloads:
            try:
                response = requests.post(
                    DOCTOR_ENDPOINT,
                    json={
                        "name": payload,
                        "specialty": "Cardiology"
                    },
                    timeout=10
                )
                
                self.log_test_result(
                    f"POST /doctor - SQL Injection: {payload[:30]}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing SQL injection {payload}: {str(e)}")
    
    def test_post_doctor_xss_attack(self):
        """Test POST /doctor với XSS attempts"""
        logger.info("\n=== Testing POST /doctor - XSS Attack ===")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]
        
        for payload in xss_payloads:
            try:
                response = requests.post(
                    DOCTOR_ENDPOINT,
                    json={
                        "name": payload,
                        "specialty": "Cardiology"
                    },
                    timeout=10
                )
                
                self.log_test_result(
                    f"POST /doctor - XSS: {payload[:30]}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing XSS {payload}: {str(e)}")
    
    def test_put_doctor_no_auth(self):
        """Test PUT /doctor không có authentication"""
        logger.info("\n=== Testing PUT /doctor - No Authentication ===")
        
        try:
            response = requests.put(
                DOCTOR_ENDPOINT,
                json={
                    "id": 1,
                    "name": "Dr. Updated",
                    "specialty": "Neurology"
                },
                timeout=10
            )
            
            self.log_test_result(
                "PUT /doctor - No Auth Token",
                expected_status=401,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_put_doctor_no_auth: {str(e)}")
    
    def test_put_doctor_invalid_id(self):
        """Test PUT /doctor với ID không hợp lệ"""
        logger.info("\n=== Testing PUT /doctor - Invalid ID ===")
        
        invalid_ids = [-1, 0, 999999, "abc", None]
        
        for invalid_id in invalid_ids:
            try:
                response = requests.put(
                    DOCTOR_ENDPOINT,
                    json={
                        "id": invalid_id,
                        "name": "Dr. Test",
                        "specialty": "Cardiology"
                    },
                    timeout=10
                )
                
                self.log_test_result(
                    f"PUT /doctor - Invalid ID: {invalid_id}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing invalid ID {invalid_id}: {str(e)}")
    
    def test_put_doctor_missing_fields(self):
        """Test PUT /doctor thiếu trường bắt buộc"""
        logger.info("\n=== Testing PUT /doctor - Missing Fields ===")
        
        try:
            response = requests.put(
                DOCTOR_ENDPOINT,
                json={
                    "id": 1
                    # Missing name and specialty
                },
                timeout=10
            )
            
            self.log_test_result(
                "PUT /doctor - Missing name & specialty",
                expected_status=400,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_put_doctor_missing_fields: {str(e)}")
    
    def test_put_doctor_day_no_auth(self):
        """Test PUT /doctor/day không có authentication"""
        logger.info("\n=== Testing PUT /doctor/day - No Authentication ===")
        
        try:
            response = requests.put(
                DOCTOR_DAY_ENDPOINT,
                json={
                    "doctorId": 1,
                    "maxPatients": 20,
                    "date": "2025-12-16"
                },
                timeout=10
            )
            
            self.log_test_result(
                "PUT /doctor/day - No Auth Token",
                expected_status=401,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_put_doctor_day_no_auth: {str(e)}")
    
    def test_put_doctor_day_invalid_data(self):
        """Test PUT /doctor/day với dữ liệu không hợp lệ"""
        logger.info("\n=== Testing PUT /doctor/day - Invalid Data ===")
        
        test_cases = [
            ({"doctorId": -1, "maxPatients": 20}, "Negative doctor ID"),
            ({"doctorId": 1, "maxPatients": -5}, "Negative max patients"),
            ({"doctorId": 1, "maxPatients": 0}, "Zero max patients"),
            ({"doctorId": 1, "maxPatients": 1000}, "Unrealistic max patients"),
            ({"doctorId": "abc", "maxPatients": 20}, "String doctor ID"),
        ]
        
        for payload, description in test_cases:
            try:
                response = requests.put(
                    DOCTOR_DAY_ENDPOINT,
                    json=payload,
                    timeout=10
                )
                
                self.log_test_result(
                    f"PUT /doctor/day - {description}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing {description}: {str(e)}")
    
    def test_delete_doctor_no_auth(self):
        """Test DELETE /doctor/{ids} không có authentication"""
        logger.info("\n=== Testing DELETE /doctor/{ids} - No Authentication ===")
        
        try:
            response = requests.delete(
                f"{DOCTOR_ENDPOINT}/1",
                timeout=10
            )
            
            self.log_test_result(
                "DELETE /doctor/{ids} - No Auth Token",
                expected_status=401,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_delete_doctor_no_auth: {str(e)}")
    
    def test_delete_doctor_invalid_id(self):
        """Test DELETE /doctor/{ids} với ID không hợp lệ"""
        logger.info("\n=== Testing DELETE /doctor/{ids} - Invalid ID ===")
        
        invalid_ids = ["-1", "0", "abc", "999999", "'; DROP TABLE doctors; --"]
        
        for invalid_id in invalid_ids:
            try:
                response = requests.delete(
                    f"{DOCTOR_ENDPOINT}/{invalid_id}",
                    timeout=10
                )
                
                self.log_test_result(
                    f"DELETE /doctor/{{ids}} - Invalid ID: {invalid_id}",
                    expected_status=400,
                    actual_status=response.status_code,
                    response_data=response.text,
                    test_type="BLOCK"
                )
            except Exception as e:
                logger.error(f"Error testing invalid ID {invalid_id}: {str(e)}")
    
    def test_delete_doctor_unauthorized_user(self):
        """Test DELETE /doctor/{ids} với user không có quyền"""
        logger.info("\n=== Testing DELETE /doctor/{ids} - Unauthorized User ===")
        
        try:
            headers = {
                "Authorization": "Bearer user_without_delete_permission"
            }
            response = requests.delete(
                f"{DOCTOR_ENDPOINT}/1",
                headers=headers,
                timeout=10
            )
            
            self.log_test_result(
                "DELETE /doctor/{ids} - Unauthorized User",
                expected_status=403,
                actual_status=response.status_code,
                response_data=response.text,
                test_type="BLOCK"
            )
        except Exception as e:
            logger.error(f"Error in test_delete_doctor_unauthorized_user: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting - gửi nhiều request liên tiếp"""
        logger.info("\n=== Testing Rate Limiting ===")
        
        try:
            blocked_count = 0
            for i in range(20):  # Gửi 20 requests liên tiếp
                response = requests.post(
                    DOCTOR_ENDPOINT,
                    json={"name": f"Dr. Test {i}"},
                    timeout=10
                )
                
                if response.status_code == 429:  # Too Many Requests
                    blocked_count += 1
            
            if blocked_count > 0:
                logger.info(f"✓ Rate limiting ACTIVE - {blocked_count}/20 requests blocked")
                self.results["blocked"] += 1
                self.results["passed"] += 1
            else:
                logger.warning("✗ Rate limiting NOT ACTIVE - All requests went through")
                self.results["failed"] += 1
            
            self.results["total_tests"] += 1
            
        except Exception as e:
            logger.error(f"Error in test_rate_limiting: {str(e)}")
    
    def run_all_tests(self):
        """Chạy tất cả các test cases"""
        logger.info("=" * 80)
        logger.info("BẮT ĐẦU KIỂM THỬ API DOCTOR CONTROLLER")
        logger.info("=" * 80)
        
        # POST /doctor tests
        self.test_post_doctor_no_auth()
        self.test_post_doctor_invalid_token()
        self.test_post_doctor_missing_fields()
        self.test_post_doctor_sql_injection()
        self.test_post_doctor_xss_attack()
        
        # PUT /doctor tests
        self.test_put_doctor_no_auth()
        self.test_put_doctor_invalid_id()
        self.test_put_doctor_missing_fields()
        
        # PUT /doctor/day tests
        self.test_put_doctor_day_no_auth()
        self.test_put_doctor_day_invalid_data()
        
        # DELETE /doctor/{ids} tests
        self.test_delete_doctor_no_auth()
        self.test_delete_doctor_invalid_id()
        self.test_delete_doctor_unauthorized_user()
        
        # Rate limiting test
        self.test_rate_limiting()
        
        # In báo cáo tổng kết
        self.print_summary()
    
    def print_summary(self):
        """In báo cáo tổng kết"""
        logger.info("\n" + "=" * 80)
        logger.info("TỔNG KẾT KẾT QUẢ KIỂM THỬ")
        logger.info("=" * 80)
        logger.info(f"Tổng số test cases: {self.results['total_tests']}")
        logger.info(f"✓ Passed/Blocked: {self.results['passed']} ({self.results['passed']/self.results['total_tests']*100:.1f}%)")
        logger.info(f"✗ Failed: {self.results['failed']} ({self.results['failed']/self.results['total_tests']*100:.1f}%)")
        logger.info(f"🛡️  Requests blocked: {self.results['blocked']}")
        logger.info("=" * 80)
        
        # Lưu kết quả chi tiết vào file JSON
        output_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n📄 Chi tiết kết quả đã được lưu vào: {output_file}")


def main():
    """Hàm main để chạy test"""
    tester = DoctorAPITester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
