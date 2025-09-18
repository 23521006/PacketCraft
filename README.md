# PacketCraft

## Giới thiệu
Đây là code demo.

## Cấu trúc thư mục
```
project/
│── backend/
│   └── app.py         # Flask backend
│── frontend/
│   └── ...            # File HTML/CSS/JS cho ElectronJS
│── main.js
│── package.json       # Cấu hình ElectronJS
│── README.md          # Tài liệu hướng dẫn
```

## Cài đặt môi trường

### 1. Cài đặt Python & Flask
- Cài đặt Python (phiên bản 3.8+).
- Mở terminal và chạy lệnh:
```bash
pip install flask
```

### 2. Cài đặt Node.js & ElectronJS
- Cài đặt Node.js (phiên bản 16+).
- Trong thư mục dự án, cài đặt ElectronJS:
```bash
npm install
```

## Chạy ứng dụng

### 1. Chạy backend (Python Flask)
Mở terminal trong thư mục `backend/` và chạy:
```bash
python app.py
```

### 2. Chạy frontend (ElectronJS)
Mở terminal trong thư mục gốc dự án và chạy:
```bash
npm start
```

Ứng dụng sẽ kết nối giữa **Flask backend** và **ElectronJS frontend**.
