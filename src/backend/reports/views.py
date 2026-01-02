"""
Report API Views.

Thin views that delegate to service layer.
"""
import logging

from authentication.permissions import IsAuditorOrAdmin
from celery.result import AsyncResult
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from django.http import FileResponse

from .services import ReportType, get_report_service
from .tasks import generate_pdf_report_task

logger = logging.getLogger(__name__)


class ReportDownloadView(APIView):
    """
    Download a generated report by filename.
    """

    permission_classes = [permissions.IsAuthenticated, IsAuditorOrAdmin]

    def get(self, request, filename):
        """Download a report by filename."""
        service = get_report_service()
        filepath = service.get_report_path(filename)

        if not filepath:
            return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

        return FileResponse(open(filepath, "rb"), content_type="application/pdf", as_attachment=True, filename=filename)


class ReportGenerationView(APIView):
    """
    API endpoint for generating PDF security reports.

    Supports three report types:
    - executive: High-level summary for leadership
    - technical: Detailed findings for security teams
    - compliance: NIST/ISO 27001 compliance mapping
    """

    permission_classes = [permissions.IsAuthenticated, IsAuditorOrAdmin]

    def post(self, request):
        """
        Generate a PDF report for a completed scan.

        Request body:
        {
            "scan_id": "<uuid>",
            "report_type": "executive" | "technical" | "compliance",
            "async": true | false (optional, default: true),
            "company_name": "Organization Name" (optional)
        }
        """
        scan_id = request.data.get("scan_id")
        report_type = request.data.get("report_type", "executive")
        async_generation = request.data.get("async", True)
        company_name = request.data.get("company_name", "Organization")

        # Validate inputs
        if not scan_id:
            return Response({"error": "scan_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        if report_type not in [t.value for t in ReportType]:
            return Response(
                {"error": f"Invalid report_type. Must be one of: {[t.value for t in ReportType]}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify scan exists and is completed
        from scanning.models import Scan

        try:
            scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        if scan.status != Scan.Status.COMPLETED:
            return Response(
                {"error": "Report can only be generated for completed scans"}, status=status.HTTP_400_BAD_REQUEST
            )

        if async_generation:
            # Queue async report generation
            task = generate_pdf_report_task.delay(
                scan_id=str(scan_id),
                report_type=report_type,
                company_name=company_name,
                requested_by_id=str(request.user.id),
            )

            logger.info(
                f"Report generation queued: scan={scan_id}, type={report_type}, "
                f"task={task.id}, user={request.user.email}"
            )

            return Response(
                {
                    "message": "Report generation started",
                    "task_id": task.id,
                    "scan_id": str(scan_id),
                    "report_type": report_type,
                    "status": "processing",
                },
                status=status.HTTP_202_ACCEPTED,
            )
        else:
            # Synchronous generation
            try:
                service = get_report_service()
                result = service.generate_report(
                    scan_id=str(scan_id), report_type=report_type, company_name=company_name
                )

                # Return file
                return FileResponse(
                    open(result.file_path, "rb"),
                    content_type="application/pdf",
                    as_attachment=True,
                    filename=result.filename,
                )

            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Report generation failed: {e}", exc_info=True)
                return Response({"error": "Report generation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        """
        Get report generation status or download completed report.

        Query parameters:
        - task_id: Celery task ID to check status
        """
        task_id = request.query_params.get("task_id")

        if not task_id:
            return Response({"error": "task_id query parameter required"}, status=status.HTTP_400_BAD_REQUEST)

        result = AsyncResult(task_id)

        if result.state == "PENDING":
            return Response({"task_id": task_id, "status": "pending", "message": "Report generation is queued"})
        elif result.state == "STARTED":
            return Response({"task_id": task_id, "status": "processing", "message": "Report is being generated"})
        elif result.state == "SUCCESS":
            report_info = result.result
            return Response({"task_id": task_id, "status": "completed", "report": report_info})
        elif result.state == "FAILURE":
            return Response(
                {"task_id": task_id, "status": "failed", "error": str(result.result)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            return Response({"task_id": task_id, "status": result.state.lower()})
