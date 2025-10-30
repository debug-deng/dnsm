# Paso 1: Usar una imagen base oficial de Python.
# 'slim' es una versión ligera que es ideal para producción.
FROM python:3.12-slim

# Paso 2: Establecer el directorio de trabajo dentro del contenedor.
# Todas las acciones posteriores se realizarán en esta carpeta.
WORKDIR /app

# Paso 3: Copiar primero el archivo de dependencias.
# Esto aprovecha el caché de Docker. Si este archivo no cambia,
# no se volverán a instalar las dependencias en futuras construcciones.
COPY requirements.txt .

# Paso 4: Instalar las dependencias de Python.
# --no-cache-dir reduce el tamaño de la imagen final.
RUN pip install --no-cache-dir -r requirements.txt

# Paso 5: Copiar el resto de los archivos del proyecto al contenedor.
# Esto incluye app.py, la carpeta 'static' y la carpeta 'templates'.
COPY . .

# Paso 6: Exponer el puerto en el que la aplicación se ejecuta DENTRO del contenedor.
# Esto es para documentación y para que Docker sepa qué puerto usa la app.
EXPOSE 500

# Paso 7: El comando para ejecutar la aplicación cuando se inicie el contenedor.
CMD ["python", "app.py"]