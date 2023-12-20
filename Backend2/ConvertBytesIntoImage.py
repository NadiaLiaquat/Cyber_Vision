import numpy as np
from PIL import Image
import uuid
from Backend2.SaveBytesFileLocation import SaveBytesFilesLocationC
from Backend2.SaveImageLocationC import SaveImageLocationC
import os

class ConversionBytesIntoImage:
    # import numpy as np
    # from PIL import Image
    #
    # def create_grayscale_image(file_path, image_size):
    #     # Read the malware binaries
    #     with open(file_path, 'rb') as f:
    #         binary_data = f.read()
    #
    #     # Convert to matrix
    #     matrix = np.frombuffer(binary_data, dtype=np.uint8)
    #
    #     # Reshape the matrix
    #     matrix = matrix[:image_size[0] * image_size[1]]  # Trim excess elements if necessary
    #     matrix = matrix.reshape(image_size)
    #
    #     # Convert to grayscale image
    #     image = Image.fromarray(matrix, mode='L')
    #
    #     return image
    #
    # # Example usage
    # # file_path = 'D:\ConversionOfFile\ConvertedFiles\WhatsAppSetup.bytes'
    # file_path = 'D:\ConversionOfFile\AnyFile\Brackets.Release.1.14.msi'
    #
    # image_size = (200, 200)  # Desired size of the grayscale image
    #
    # # Create the grayscale image
    # grayscale_image = create_grayscale_image(file_path, image_size)
    #
    # # Display or save the grayscale image as needed
    # grayscale_image.show()
    # =====================================================================================


    def create_grayscale_image(self,file_path, image_size, save_path):
        # Read the malware binaries
        with open(file_path, 'rb') as f:
            binary_data = f.read()

        # Convert to matrix
        matrix = np.frombuffer(binary_data, dtype=np.uint8)

        # Reshape the matrix
        matrix = matrix[:image_size[0] * image_size[1]]  # Trim excess elements if necessary
        matrix = matrix.reshape(image_size)

        # Convert to grayscale image
        image = Image.fromarray(matrix, mode='L')

        # Save the grayscale image
        image.save(save_path)
    def bytesIntoImage_fun(self):
        # Example usage
        getBytesFile=SaveBytesFilesLocationC()

        file_path = getBytesFile.getBytesPath()
        image_size = (64, 64)  # Desired size of the grayscale image
        random_file_name = str(uuid.uuid4())

        # save_path = f'E:\Python-Projects\Front_end\Backend2\images\{random_file_name}.png'  # Path to save the grayscale image



        os.makedirs('Front_end/Backend2/images', exist_ok=True)

        save_path =  f'Front_end/Backend2/images/{random_file_name}.png'


        image_saver=SaveImageLocationC()

        image_saver.setImagePath(save_path)
        # Create and save the grayscale image
        self.create_grayscale_image(file_path, image_size, save_path)
        print("Image is Generated is Successfully")