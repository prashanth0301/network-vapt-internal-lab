from typing import Optional

from loguru import logger

from app.models.cve import CVE


class RiskScore:
    def __init__(
        self,
        priority: str,
        business_risk: float,
        technical_risk: float,
        exploitability: float,
        priority_score: float,
    ):
        self.priority = priority
        self.business_risk = business_risk
        self.technical_risk = technical_risk
        self.exploitability = exploitability
        self.priority_score = priority_score

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "business_risk": self.business_risk,
            "technical_risk": self.technical_risk,
            "exploitability": self.exploitability,
            "priority_score": self.priority_score,
        }


class RiskEngine:
    SEVERITY_WEIGHTS = {
        "Critical": 10.0,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5,
        "Info": 0.0,
    }

    def calculate_technical_risk(
        self,
        cvss_score: Optional[float] = None,
        exploitability_score: Optional[float] = None,
        impact_score: Optional[float] = None,
    ) -> float:
        if cvss_score is not None:
            return round(min(cvss_score, 10.0), 1)
        if exploitability_score is not None and impact_score is not None:
            return round(min((exploitability_score + impact_score) / 2, 10.0), 1)
        return 0.0

    def calculate_exploitability(
        self,
        cvss_exploitability: Optional[float] = None,
        epss_score: Optional[float] = None,
        has_exploit: bool = False,
        kev_status: bool = False,
    ) -> float:
        score = 0.0
        if cvss_exploitability is not None:
            score += cvss_exploitability * 2.0
        if epss_score is not None:
            score += epss_score * 5.0
        if has_exploit:
            score += 3.0
        if kev_status:
            score += 2.0
        return round(min(score, 10.0), 1)

    def calculate_business_risk(
        self,
        technical_risk: float,
        exploitability: float,
        exposure: float = 1.0,
        is_open_port: bool = True,
    ) -> float:
        base = (technical_risk * 0.5) + (exploitability * 0.3)
        if is_open_port:
            base *= 1.2
        base *= exposure
        return round(min(base, 10.0), 1)

    def calculate_priority_score(
        self,
        technical_risk: float,
        exploitability: float,
        business_risk: float,
    ) -> float:
        return round(
            (technical_risk * 0.4) + (exploitability * 0.35) + (business_risk * 0.25),
            1,
        )

    def score_from_priority(self, priority_score: float) -> str:
        if priority_score >= 8.0:
            return "Critical"
        if priority_score >= 6.0:
            return "High"
        if priority_score >= 4.0:
            return "Medium"
        if priority_score >= 1.0:
            return "Low"
        return "Info"

    def calculate(
        self,
        cvss_score: Optional[float] = None,
        cvss_exploitability: Optional[float] = None,
        impact_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        has_exploit: bool = False,
        kev_status: bool = False,
        exposure: float = 1.0,
        is_open_port: bool = True,
    ) -> RiskScore:
        technical = self.calculate_technical_risk(
            cvss_score=cvss_score,
            exploitability_score=cvss_exploitability,
            impact_score=impact_score,
        )
        exploitability = self.calculate_exploitability(
            cvss_exploitability=cvss_exploitability,
            epss_score=epss_score,
            has_exploit=has_exploit,
            kev_status=kev_status,
        )
        business = self.calculate_business_risk(
            technical_risk=technical,
            exploitability=exploitability,
            exposure=exposure,
            is_open_port=is_open_port,
        )
        priority_score = self.calculate_priority_score(
            technical_risk=technical,
            exploitability=exploitability,
            business_risk=business,
        )
        priority = self.score_from_priority(priority_score)
        return RiskScore(
            priority=priority,
            business_risk=business,
            technical_risk=technical,
            exploitability=exploitability,
            priority_score=priority_score,
        )

    def calculate_for_cve(
        self,
        cve: CVE,
        has_exploit: bool = False,
        exposure: float = 1.0,
        is_open_port: bool = True,
    ) -> RiskScore:
        return self.calculate(
            cvss_score=cve.cvss_score,
            cvss_exploitability=cve.exploitability_score,
            impact_score=cve.impact_score,
            epss_score=cve.epss_score,
            has_exploit=has_exploit or cve.exploit_available,
            kev_status=cve.kev_status,
            exposure=exposure,
            is_open_port=is_open_port,
        )


risk_engine = RiskEngine()
