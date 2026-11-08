import logging
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.message import MessageScanRequest, MessageScanResponse
from backend.app.services.scanner.message_analyzer import message_analyzer
from backend.app.services.ai.gemini_explainer import gemini_explainer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/analyze", response_model=MessageScanResponse, tags=["Message Triage"])
async def analyze_message(request: MessageScanRequest):
    """
    Analyzes suspected scam messages (SMS, WhatsApp, Email, Job offers, Banking alerts).
    - Identifies artificial urgency and psychological coercion
    - Detects authority & institution impersonation
    - Extracts suspicious links, phone numbers, and payment requests
    - Generates actionable safety recommendations
    - Augments with cognitive plain-language explanation
    """
    raw = request.message_text if request.message_text else ""
    text = raw.strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty."
        )

    # 1. Deterministic heuristic & pattern analysis (ground truth)
    response = message_analyzer.analyze(text, channel_type=request.channel_type or "AUTO")

    # 2. Cognitive plain-language explanation (Gemini or heuristic fallback)
    try:
        tactic_names = response.manipulation_tactics or [t.tactic for t in response.detected_tactics]
        ai_exp = await gemini_explainer.explain_message_verdict(
            message_text=text,
            verdict=response.verdict,
            risk_score=response.risk_score,
            scam_category=response.scam_category,
            detected_tactics=tactic_names,
            extracted_links=response.extracted_links,
        )
        response.ai_explanation = ai_exp
    except Exception as exc:
        logger.warning(f"Error enriching message with AI explanation: {exc}")
        # Fallback ensures endpoint reliability even under AI failure

    return response
