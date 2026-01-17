CC = x86_64-w64-mingw32-gcc

# خيارات المترجم
# -I لمحلد الـ include
# -Wall لإظهار التحذيرات
# -O2 للتحسين (Optimization)
SRCS = MalDives-Framework/src/main.c MalDives-Framework/src/xor.c
CFLAGS = -I./MalDives-Framework/include -Wall -O2

# الملفات المطلوبة
SRCS = src/main.c src/xor.c
OBJS = $(SRCS:.c=.o)

# اسم البرنامج النهائي
TARGET = ../bin/Release/playingx.exe

# القاعدة الأساسية
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)
	@echo "[+] Build Successful: $(TARGET)"

# قاعدة تحويل الـ .c لـ .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# تنظيف الملفات المؤقتة
clean:
	rm -f src/*.o $(TARGET)