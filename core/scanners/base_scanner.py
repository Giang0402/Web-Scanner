class BaseScanner:
    """Lớp cơ sở trừu tượng cho tất cả các plugin quét."""
    def __init__(self, session, payloads):
        """
        Khởi tạo plugin.
        :param session: Đối tượng session của thư viện requests để thực hiện HTTP request.
        :param payloads: Một từ điển chứa tất cả các payload đã được tải.
        """
        self.session = session
        # Lấy danh sách payload tương ứng với tên của plugin
        self.payloads = payloads.get(self.name, [])

    @property
    def name(self):
        """Tên của plugin, phải khớp với tên tệp payload (ví dụ: 'xss')."""
        raise NotImplementedError("Mỗi plugin phải định nghĩa một 'name'.")

    def scan(self, target):
        """
        Phương thức chính để thực hiện quét trên một mục tiêu.
        :param target: Một từ điển chứa thông tin mục tiêu {'type': 'url'/'form', 'value': ...}.
        :return: Một danh sách các lỗ hổng được tìm thấy (dạng từ điển).
        """
        raise NotImplementedError("Mỗi plugin phải triển khai phương thức 'scan'.")