import os
from ._logger import logger
import shutil


class _Template(object):

    def init_gemini_template(flask_template_folder):
      """
      This function initializes a Gemini Protector GUI template by copying files from a resource
      folder to a specified Flask template folder.
      
      :param flask_template_folder: The parameter `flask_template_folder` is a string representing the
      path to the folder where Flask templates are stored
      """
      try:
          template_directory = os.path.join(
              flask_template_folder, r'gemini-protector-gui')

          package_directory = os.path.abspath(os.path.dirname(__file__))
          shutil.rmtree(template_directory, ignore_errors=True)
          shutil.copytree(package_directory +
                          '/resource/templates', template_directory)
      except Exception as e:
          logger.error(
              "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Template.init_gemini_template', e))

    def init_gemini_static(flask_static_folder):
        try:
            static_directory = os.path.join(
                flask_static_folder, r'gemini-protector-static')

            package_directory = os.path.abspath(os.path.dirname(__file__))
            shutil.rmtree(static_directory, ignore_errors=True)
            shutil.copytree(package_directory +
                            '/resource/assets', static_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Template.gemini_static_file', e))
