"""Screenshot OCR with graceful fallback: EasyOCR -> Tesseract (pytesseract) -> manual paste."""
import io
import shutil

_reader = None


def status() -> dict:
    s = {"easyocr": False, "tesseract": False, "opencv": False}
    try:
        import easyocr  # noqa: F401
        s["easyocr"] = True
    except Exception:
        pass
    try:
        import pytesseract  # noqa: F401
        s["tesseract"] = shutil.which("tesseract") is not None
    except Exception:
        pass
    try:
        import cv2  # noqa: F401
        s["opencv"] = True
    except Exception:
        pass
    s["available"] = s["easyocr"] or s["tesseract"]
    return s


def _preprocess(img):
    """Grayscale + upscale small images + adaptive threshold (OpenCV) to help OCR on phone screenshots."""
    try:
        import cv2
        import numpy as np
        arr = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2GRAY)
        h, w = arr.shape
        if max(h, w) < 1400:
            arr = cv2.resize(arr, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        arr = cv2.fastNlMeansDenoising(arr, None, 10, 7, 21)
        from PIL import Image
        return Image.fromarray(arr)
    except Exception:
        return img.convert("L")


def extract_text(image_bytes: bytes):
    """Returns (text, engine_name, error). Never raises."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception as e:
        return "", None, f"Could not read image: {e}"
    st = status()
    errors = []
    if st["easyocr"]:
        try:
            global _reader
            import easyocr
            import numpy as np
            if _reader is None:
                _reader = easyocr.Reader(["en"], gpu=False, verbose=False)
            text = "\n".join(_reader.readtext(np.array(_preprocess(img)), detail=0, paragraph=True))
            if text.strip():
                return text, "EasyOCR", None
        except Exception as e:
            errors.append(f"EasyOCR: {e}")
    if st["tesseract"]:
        try:
            import pytesseract
            langs = set(pytesseract.get_languages(config=""))
            lang = "eng+tel" if "tel" in langs else "eng"
            text = pytesseract.image_to_string(_preprocess(img), lang=lang)
            return text, "Tesseract", None
        except Exception as e:
            errors.append(f"Tesseract: {e}")
    return "", None, "; ".join(errors) or "No OCR engine installed."
