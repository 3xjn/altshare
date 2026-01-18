using System.Security.Claims;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("api/group")]
    [Tags("group")]
    [Authorize]
    public class GroupController : Controller
    {
        private readonly GroupService _groupService;

        public GroupController(GroupService groupService)
        {
            _groupService = groupService;
        }

        [HttpGet]
        public async Task<IActionResult> GetGroups()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            var groups = await _groupService.GetGroupsAsync(email);
            var response = groups.Select(group => new
            {
                id = group.Id.ToString(),
                name = group.Name,
                usesMasterKey = group.UsesMasterKey,
                encryptedGroupKey = group.EncryptedGroupKey
            });

            return Ok(response);
        }

        [HttpPost]
        public async Task<IActionResult> CreateGroup([FromBody] CreateGroupRequest request)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            if (string.IsNullOrWhiteSpace(request.Name) ||
                string.IsNullOrWhiteSpace(request.EncryptedGroupKey))
            {
                return BadRequest(new { message = "Group name and key are required." });
            }

            var group = await _groupService.CreateGroupAsync(
                email,
                request.Name,
                request.EncryptedGroupKey
            );

            if (group == null)
            {
                return BadRequest(new { message = "Unable to create group." });
            }

            return Ok(new
            {
                id = group.Id.ToString(),
                name = group.Name,
                usesMasterKey = group.UsesMasterKey
            });
        }
    }
}
