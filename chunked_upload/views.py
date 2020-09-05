import re

from django.views.generic import View
from django.shortcuts import get_object_or_404
from django.core.files.base import ContentFile
from django.utils import timezone

from .settings import MAX_BYTES
from .models import ChunkedUpload
from .response import Response
from .constants import HTTPStatus
from .exceptions import ChunkedUploadError


class ChunkedUploadBaseView(View):
    """
    Base view for the rest of chunked upload views.
    """

    # Has to be a ChunkedUpload subclass
    model = ChunkedUpload

    def get_queryset(self, request):
        """
        Get (and filter) ChunkedUpload queryset.
        """
        return self.model.objects.all()

    def validate(self, request):
        """
        Placeholder method to define extra validation.
        Must raise ChunkedUploadError if validation fails.
        """

    def get_response_data(self, chunked_upload, request):
        """
        Data for the response. Should return a dictionary-like object.
        Called *only* if POST is successful.
        """
        return {}

    def pre_save(self, chunked_upload, request, new=False):
        """
        Placeholder method for calling before saving an object.
        May be used to set attributes on the object that are implicit
        in either the request, or the url.
        """

    def save(self, chunked_upload, request, new=False):
        """
        Method that calls save(). Overriding may be useful is save() needs
        special args or kwargs.
        """
        chunked_upload.save()

    def post_save(self, chunked_upload, request, new=False):
        """
        Placeholder method for calling after saving an object.
        """

    def _save(self, chunked_upload):
        """
        Wraps save() method.
        """
        new = chunked_upload.id is None
        self.pre_save(chunked_upload, self.request, new=new)
        self.save(chunked_upload, self.request, new=new)
        self.post_save(chunked_upload, self.request, new=new)

    def check_permissions(self, request):
        """
        Grants permission to start/continue an upload based on the request.
        """

    def on_completion(self, uploaded_file, request):
        """
        Placeholder method to define what to do when upload is complete.
        """

    def _post(self, request, *args, **kwargs):
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests.
        """
        try:
            self.check_permissions(request)
            return self._post(request, *args, **kwargs)
        except ChunkedUploadError as error:
            return Response(error.data, status=error.status_code)


class ChunkedUploadView(ChunkedUploadBaseView):
    """
    Uploads large files in multiple chunks. Also, has the ability to resume
    if the upload is interrupted.

    Method `on_completion` is a placeholder to define what to do when upload
    is complete.
    """

    field_name = 'file'
    content_range_header = 'HTTP_CONTENT_RANGE'
    content_range_pattern = re.compile(
        r'^bytes (?P<start>\d+)-(?P<end>\d+)/(?P<total>\d+)$'
    )
    max_bytes = MAX_BYTES  # Max amount of data that can be uploaded
    # If `fail_if_no_header` is True, an exception will be raised if the
    # content-range header is not found. Default is False to match Jquery File
    # Upload behavior (doesn't send header if the file is smaller than chunk)
    fail_if_no_header = False

    # I wouldn't recommend to turn off the md5 check, unless is really
    # impacting your performance. Proceed at your own risk.
    do_md5_check = True

    def get_extra_attrs(self, request):
        """
        Extra attribute values to be passed to the new ChunkedUpload instance.
        Should return a dictionary-like object.
        """
        return {}

    def get_max_bytes(self, request):
        """
        Used to limit the max amount of data that can be uploaded. `None` means
        no limit.
        You can override this to have a custom `max_bytes`, e.g. based on
        logged user.
        """

        return self.max_bytes

    def create_chunked_upload(self, save=False, **attrs):
        """
        Creates new chunked upload instance. Called if no 'upload_id' is
        found in the POST data.
        """
        chunked_upload = self.model(**attrs)
        # file starts empty
        chunked_upload.file.save(name='', content=ContentFile(''), save=save)
        return chunked_upload

    def is_valid_chunked_upload(self, chunked_upload):
        """
        Check if chunked upload has already expired.
        """
        if chunked_upload.expired:
            chunked_upload.delete()
            raise ChunkedUploadError(status=HTTPStatus.HTTP_410_GONE,
                                     detail='Upload has expired')

    def get_response_data(self, chunked_upload, request):
        """
        Data for the response. Should return a dictionary-like object.
        """
        return {
            'upload_id': chunked_upload.upload_id,
            'offset': chunked_upload.offset,
            'expires': chunked_upload.expires_on
        }

    def md5_check(self, chunked_upload, md5):
        """
        Verify if md5 checksum sent by client matches generated md5.
        """
        if chunked_upload.md5 != md5:
            raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                     detail='md5 checksum does not match')

    def _post(self, request, *args, **kwargs):
        chunk = request.FILES.get(self.field_name)
        if chunk is None:
            raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                     detail='No chunk file was submitted')
        self.validate(request)

        upload_id = request.POST.get('upload_id')
        if upload_id:
            chunked_upload = get_object_or_404(self.get_queryset(request),
                                               upload_id=upload_id)
            self.is_valid_chunked_upload(chunked_upload)
        else:
            attrs = {'filename': chunk.name}

            attrs.update(self.get_extra_attrs(request))
            chunked_upload = self.create_chunked_upload(save=False, **attrs)

        content_range = request.META.get(self.content_range_header, '')
        match = self.content_range_pattern.match(content_range)
        if match:
            start = int(match.group('start'))
            end = int(match.group('end'))
            total = int(match.group('total'))
        elif self.fail_if_no_header:
            raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                     detail='Error in request headers')
        else:
            # Use the whole size when HTTP_CONTENT_RANGE is not provided
            start = 0
            end = chunk.size - 1
            total = chunk.size

        chunk_size = end - start + 1
        max_bytes = self.get_max_bytes(request)

        if max_bytes is not None and total > max_bytes:
            raise ChunkedUploadError(
                status=HTTPStatus.HTTP_400_BAD_REQUEST,
                detail='Size of file exceeds the limit (%s bytes)' % max_bytes
            )
        if chunked_upload.offset != start:
            raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                     detail='Offsets do not match',
                                     offset=chunked_upload.offset)
        if chunk.size != chunk_size:
            raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                     detail="File size doesn't match headers")

        chunked_upload.append_chunk(chunk, chunk_size=chunk_size, save=False)

        if total == (end + 1):
            if self.do_md5_check:
                md5 = request.POST.get('md5')

                if not md5:
                    raise ChunkedUploadError(status=HTTPStatus.HTTP_400_BAD_REQUEST,
                                             detail="'md5' is required")

                self.md5_check(chunked_upload, md5)

            self.on_completion(chunked_upload.get_uploaded_file(), request)

            if chunked_upload.exists:
                chunked_upload.file.delete()

            chunked_upload.delete()
        else:
            self._save(chunked_upload)

        return Response(self.get_response_data(chunked_upload, request),
                        status=HTTPStatus.HTTP_200_OK)
