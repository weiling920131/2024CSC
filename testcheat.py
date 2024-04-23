import os
import mosspy

userid = 749465543


m = mosspy.Moss(userid, "cpp")  # 设置语言为 C++

# 设置基准文件夹和提交文件夹
base_folder = "ref"
submission_folder = "110550126"

# 添加基准文件夹中的文件
for filename in os.listdir(base_folder):
    m.addFile(os.path.join(base_folder, filename))

# 添加提交文件夹中的文件
for root, dirs, files in os.walk(submission_folder):
    for filename in files:
        m.addFile(os.path.join(root, filename))

# 发送比较请求
url = m.send()

print("Report Url: " + url)