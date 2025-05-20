from flask import Flask, request, jsonify, send_from_directory, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import logging
from datetime import timedelta
import jwt as pyjwt  # 添加 PyJWT 导入
from urllib.parse import unquote

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 配置
app.config['SECRET_KEY'] = 'your-secret-key'  # 请在生产环境中更改
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inslulu.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'  # 请在生产环境中更改
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB 限制
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 初始化扩展
db = SQLAlchemy(app)
jwt = JWTManager(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    upload_folder = db.Column(db.String(120), unique=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 网页路由
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

# API路由
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logger.info(f"注册请求: {data['username']}")
        
        if User.query.filter_by(username=data['username']).first():
            logger.warning(f"用户名已存在: {data['username']}")
            return jsonify({'error': '用户名已存在'}), 400
        
        user = User(
            username=data['username'],
            upload_folder=os.path.join(app.config['UPLOAD_FOLDER'], data['username'])
        )
        user.set_password(data['password'])
        
        # 创建用户专属文件夹
        os.makedirs(user.upload_folder, exist_ok=True)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"用户注册成功: {data['username']}")
        return jsonify({'message': '注册成功'}), 201
    except Exception as e:
        logger.error(f"注册失败: {str(e)}")
        return jsonify({'error': f'注册失败: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        logger.info(f"登录请求: {data['username']}")
        
        user = User.query.filter_by(username=data['username']).first()
        
        if user and user.check_password(data['password']):
            access_token = create_access_token(
                identity=str(user.id),  # 将用户ID转换为字符串
                expires_delta=timedelta(days=1)
            )
            logger.info(f"用户登录成功: {data['username']}")
            return jsonify({
                'access_token': access_token,
                'message': '登录成功'
            }), 200
        
        logger.warning(f"登录失败: {data['username']}")
        return jsonify({'error': '用户名或密码错误'}), 401
    except Exception as e:
        logger.error(f"登录失败: {str(e)}")
        return jsonify({'error': f'登录失败: {str(e)}'}), 500

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        if 'file' not in request.files:
            logger.warning("上传请求中没有文件")
            return jsonify({'error': '没有文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            logger.warning("上传的文件名为空")
            return jsonify({'error': '没有选择文件'}), 400
        
        if not allowed_file(file.filename):
            logger.warning(f"不支持的文件类型: {file.filename}")
            return jsonify({'error': '不支持的文件类型'}), 400
        
        user_id = get_jwt_identity()
        user = db.session.get(User, int(user_id))
        
        if not user:
            logger.error(f"用户不存在: {user_id}")
            return jsonify({'error': '用户不存在'}), 404
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(user.upload_folder, filename)
        file.save(file_path)
        
        logger.info(f"文件上传成功: {filename}")
        return jsonify({
            'message': '文件上传成功',
            'filename': filename,
            'preview_url': f'/api/preview/{filename}'
        }), 200
    except Exception as e:
        logger.error(f"文件上传失败: {str(e)}")
        return jsonify({'error': f'文件上传失败: {str(e)}'}), 500

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, int(user_id))
        
        if not user:
            logger.error(f"用户不存在: {user_id}")
            return jsonify({'error': '用户不存在'}), 404
        
        files = []
        for filename in os.listdir(user.upload_folder):
            file_path = os.path.join(user.upload_folder, filename)
            if os.path.isfile(file_path):
                files.append({
                    'filename': filename,
                    'size': os.path.getsize(file_path),
                    'upload_time': os.path.getmtime(file_path),
                    'preview_url': f'/api/preview/{filename}'
                })
        
        logger.info(f"获取文件列表成功: {len(files)} 个文件")
        return jsonify({'files': files}), 200
    except Exception as e:
        logger.error(f"获取文件列表失败: {str(e)}")
        return jsonify({'error': f'获取文件列表失败: {str(e)}'}), 500

@app.route('/api/preview/<filename>')
def preview_image(filename):
    # 从请求头或 URL 参数中获取 token
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or request.args.get('token')
    if not token:
        return jsonify({'error': '未授权访问'}), 401
    
    try:
        # 使用 PyJWT 验证 token
        payload = pyjwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['sub']  # JWT 中的用户 ID 存储在 'sub' 字段
        
        user = db.session.get(User, int(user_id))
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 检查文件是否存在
        file_path = os.path.join(user.upload_folder, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': '文件不存在'}), 404
            
        # 返回图片
        return send_file(
            file_path,
            mimetype='image/jpeg'
        )
    except pyjwt.ExpiredSignatureError:
        return jsonify({'error': 'token已过期'}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({'error': '无效的token'}), 401

@app.route('/api/files/<filename>', methods=['DELETE'])
@jwt_required()
def delete_file(filename):
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, int(user_id))
        
        if not user:
            logger.error(f"用户不存在: {user_id}")
            return jsonify({'error': '用户不存在'}), 404
        
        # 对URL编码的文件名进行解码
        decoded_filename = unquote(filename)
        
        # 获取用户文件夹中的所有文件
        user_files = os.listdir(user.upload_folder)
        logger.debug(f"用户文件夹中的文件: {user_files}")
        
        # 查找匹配的文件（忽略大小写和空格）
        matching_file = None
        for file in user_files:
            # 移除文件名中的空格和下划线进行比较
            normalized_file = file.replace(' ', '').replace('_', '').lower()
            normalized_input = decoded_filename.replace(' ', '').replace('_', '').lower()
            if normalized_file == normalized_input:
                matching_file = file
                break
        
        if not matching_file:
            logger.warning(f"删除文件失败: 文件不存在 {decoded_filename}")
            return jsonify({'error': '文件不存在'}), 404
        
        file_path = os.path.join(user.upload_folder, matching_file)
        os.remove(file_path)
        logger.info(f"文件删除成功: {matching_file}")
        return jsonify({
            'message': '文件删除成功',
            'filename': matching_file
        }), 200
    except Exception as e:
        logger.error(f"删除文件失败: {str(e)}")
        return jsonify({'error': f'删除文件失败: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    logger.info("服务器启动成功")
    app.run(debug=True, port=5001) 